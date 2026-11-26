"""Receivable settlement core logic.

Domain summary (all amounts are integer cents, single simulated currency, no
bank or real payment integration):

* Operators register a receivable under a *completed* signing agreement.
* A creditor may transfer part of their unrecovered principal to another
  account.  The transfer creates a two-seat agreement bound to the
  receivable/transferor/transferee/amount, signed through the existing
  challenge flow.  Applying never freezes principal: the debtor can still pay.
* Operators confirm a transfer only against a *completed* transfer agreement;
  the current unrecovered principal decides whether the full amount can move.
  A shortfall terminates the whole transfer permanently; an unsigned
  agreement is simply not decidable yet.  An application can take effect once.
* Channel receipts are split among the creditors holding unrecovered
  principal immediately before the receipt, proportional to their holdings,
  with integer floors and the remainder distributed one cent at a time by
  largest fractional remainder (ties broken by account id ascending).
* Refunds are registered in parts against one original receipt, never
  exceeding it cumulatively, and reverse the original split lines in order of
  original amount descending (ties by account id ascending) -- the refund
  never recomputes creditor ratios at refund time.
* Every creditor has one cross-receivable settlement account with a drawable
  balance and a pending-clawback debt.  Refunds claw back balance first; any
  shortfall becomes pending deduction that future allocations absorb before
  crediting new funds.  Historical disbursement records are never rewritten.

Every public ``*_tx`` function assumes it runs inside the caller's
``BEGIN IMMEDIATE`` transaction (the idempotency wrapper provides one), so all
invariants are checked and committed atomically.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

from .errors import ApiError
from .idempotency import OpResult
from .security import (
    canonical_json_text,
    new_id,
    sha256_hex,
    utc_now,
)
from . import service as signing_service

TRANSFER_AGREEMENT_SCHEMA = "receivable-transfer-agreement/v1"


# ---------------------------------------------------------------------------
# Small row helpers
# ---------------------------------------------------------------------------


def _get_receivable_or_404(
    conn: sqlite3.Connection, receivable_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM receivables WHERE receivable_id = ?", (receivable_id,)
    ).fetchone()
    if row is None:
        raise ApiError(
            404, "RECEIVABLE_NOT_FOUND", f"Receivable {receivable_id!r} was not found."
        )
    return row


def _get_account_or_404(conn: sqlite3.Connection, account_id: str) -> sqlite3.Row:
    return signing_service.account_or_404(conn, account_id)


def _receivable_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "receivable_id": row["receivable_id"],
        "receivable_no": row["receivable_no"],
        "agreement_id": row["agreement_id"],
        "operator_account_id": row["operator_account_id"],
        "debtor": row["debtor"],
        "original_creditor_id": row["original_creditor_id"],
        "principal_cents": row["principal_cents"],
        "remaining_cents": row["remaining_cents"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


def _holdings(conn: sqlite3.Connection, receivable_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT * FROM receivable_holdings
            WHERE receivable_id = ? AND held_cents > 0
            ORDER BY account_id ASC
            """,
            (receivable_id,),
        ).fetchall()
    )


def _holding_row(
    conn: sqlite3.Connection, receivable_id: str, account_id: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM receivable_holdings WHERE receivable_id = ? AND account_id = ?",
        (receivable_id, account_id),
    ).fetchone()


def _upsert_holding(
    conn: sqlite3.Connection, receivable_id: str, account_id: str, delta_cents: int
) -> None:
    """Add ``delta_cents`` (may be negative) to one creditor's holding."""
    now = utc_now()
    row = _holding_row(conn, receivable_id, account_id)
    if row is None:
        if delta_cents < 0:
            raise ApiError(500, "HOLDING_UNDERFLOW", "Internal holding accounting error.")
        conn.execute(
            """
            INSERT INTO receivable_holdings (
                holding_id, receivable_id, account_id, held_cents, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (new_id("hold"), receivable_id, account_id, delta_cents, now),
        )
        return

    new_value = row["held_cents"] + delta_cents
    if new_value < 0:
        raise ApiError(500, "HOLDING_UNDERFLOW", "Internal holding accounting error.")
    conn.execute(
        "UPDATE receivable_holdings SET held_cents = ?, updated_at = ? WHERE holding_id = ?",
        (new_value, now, row["holding_id"]),
    )


# ---------------------------------------------------------------------------
# Settlement accounts and the append-only ledger
# ---------------------------------------------------------------------------


def _get_or_create_settlement_account(
    conn: sqlite3.Connection, account_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM settlement_accounts WHERE account_id = ?", (account_id,)
    ).fetchone()
    if row is not None:
        return row
    now = utc_now()
    conn.execute(
        """
        INSERT INTO settlement_accounts (
            account_id, available_cents, pending_deduction_cents,
            total_allocated_cents, total_clawback_cents, total_disbursed_cents,
            updated_at
        ) VALUES (?, 0, 0, 0, 0, 0, ?)
        """,
        (account_id, now),
    )
    return conn.execute(
        "SELECT * FROM settlement_accounts WHERE account_id = ?", (account_id,)
    ).fetchone()


def _ledger(
    conn: sqlite3.Connection,
    account_id: str,
    event_type: str,
    ref_type: str,
    ref_id: str,
    delta_available: int,
    delta_deduction: int,
) -> None:
    account = _get_or_create_settlement_account(conn, account_id)
    now = utc_now()
    conn.execute(
        """
        INSERT INTO settlement_ledger (
            ledger_id, account_id, event_type, ref_type, ref_id,
            delta_available, delta_deduction, balance_after, deduction_after,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id("ledg"),
            account_id,
            event_type,
            ref_type,
            ref_id,
            delta_available,
            delta_deduction,
            account["available_cents"],
            account["pending_deduction_cents"],
            now,
        ),
    )


def _credit_allocation(
    conn: sqlite3.Connection,
    account_id: str,
    gross_amount: int,
    allocation_id: str,
) -> int:
    """Credit a receipt share to an account, absorbing any clawback debt first.

    Returns the net amount actually added to the drawable balance.
    """
    account = _get_or_create_settlement_account(conn, account_id)
    now = utc_now()
    debt = account["pending_deduction_cents"]
    offset = min(debt, gross_amount)
    net = gross_amount - offset

    conn.execute(
        """
        UPDATE settlement_accounts
        SET available_cents = available_cents + ?,
            pending_deduction_cents = pending_deduction_cents - ?,
            total_allocated_cents = total_allocated_cents + ?,
            updated_at = ?
        WHERE account_id = ?
        """,
        (net, offset, gross_amount, now, account_id),
    )
    _ledger(
        conn,
        account_id,
        "allocation",
        "receipt_allocation",
        allocation_id,
        net,
        0,
    )
    if offset:
        _ledger(
            conn,
            account_id,
            "allocation_deduction_offset",
            "receipt_allocation",
            allocation_id,
            0,
            -offset,
        )
    return net


def _clawback(
    conn: sqlite3.Connection,
    account_id: str,
    amount: int,
    reversal_id: str,
) -> tuple[int, int]:
    """Reverse ``amount`` cents from one original payee's settlement account.

    Balance is clawed back first; any residual becomes pending deduction.
    Existing disbursement rows are never modified.
    Returns ``(clawed_from_balance, added_to_deduction)``.
    """
    account = _get_or_create_settlement_account(conn, account_id)
    now = utc_now()
    from_balance = min(account["available_cents"], amount)
    to_deduction = amount - from_balance

    conn.execute(
        """
        UPDATE settlement_accounts
        SET available_cents = available_cents - ?,
            pending_deduction_cents = pending_deduction_cents + ?,
            total_clawback_cents = total_clawback_cents + ?,
            updated_at = ?
        WHERE account_id = ?
        """,
        (from_balance, to_deduction, amount, now, account_id),
    )
    if from_balance:
        _ledger(
            conn,
            account_id,
            "refund_clawback_balance",
            "refund_reversal",
            reversal_id,
            -from_balance,
            0,
        )
    if to_deduction:
        _ledger(
            conn,
            account_id,
            "refund_clawback_deduction",
            "refund_reversal",
            reversal_id,
            0,
            to_deduction,
        )
    return from_balance, to_deduction


# ---------------------------------------------------------------------------
# Integer proportional split
# ---------------------------------------------------------------------------


def largest_remainder_split(
    holders: list[tuple[str, int]], total_cents: int
) -> list[tuple[str, int]]:
    """Split ``total_cents`` over holders by weight, using integer cents.

    ``holders`` is a list of ``(account_id, weight_cents)`` with positive
    weights.  Each share gets ``floor(total * weight / weight_sum)`` first;
    the leftover cents are handed out one at a time ordered by fractional
    remainder descending, ties broken by account id ascending.  The returned
    list sums exactly to ``total_cents`` and preserves input order.
    """
    if total_cents <= 0:
        return [(account_id, 0) for account_id, _ in holders]
    weight_sum = sum(weight for _, weight in holders)
    if weight_sum <= 0:
        raise ApiError(500, "SPLIT_NO_HOLDERS", "No positive holdings to split against.")

    floors: list[int] = []
    fractions: list[tuple[int, str, int]] = []  # (remainder, account_id, index)
    for index, (account_id, weight) in enumerate(holders):
        scaled = total_cents * weight
        floor_share, remainder = divmod(scaled, weight_sum)
        floors.append(floor_share)
        fractions.append((remainder, account_id, index))

    leftover = total_cents - sum(floors)
    # Largest remainder first; equal remainder -> account id ascending.
    fractions.sort(key=lambda item: (-item[0], item[1]))
    for rank in range(leftover):
        floors[fractions[rank][2]] += 1

    return [(holders[index][0], share) for index, share in enumerate(floors)]


# ---------------------------------------------------------------------------
# Receivable registration
# ---------------------------------------------------------------------------


def register_receivable_tx(
    conn: sqlite3.Connection, data: Any
) -> dict[str, Any]:
    agreement = signing_service.get_agreement_or_404(conn, data.agreement_id)
    if agreement["status"] != "completed":
        raise ApiError(
            409,
            "AGREEMENT_NOT_COMPLETED",
            "A receivable can only be registered under a fully signed (completed) agreement.",
            {"agreement_id": data.agreement_id, "status": agreement["status"]},
        )

    _get_account_or_404(conn, data.operator_account_id)
    _get_account_or_404(conn, data.original_creditor_id)

    duplicate = conn.execute(
        "SELECT * FROM receivables WHERE receivable_no = ?", (data.receivable_no,)
    ).fetchone()
    if duplicate is not None:
        raise ApiError(
            409,
            "RECEIVABLE_NO_CONFLICT",
            "A receivable with this receivable number already exists.",
            {"receivable_no": data.receivable_no, "receivable_id": duplicate["receivable_id"]},
        )

    now = utc_now()
    receivable_id = new_id("recv")
    conn.execute(
        """
        INSERT INTO receivables (
            receivable_id, receivable_no, agreement_id, operator_account_id,
            debtor, original_creditor_id, principal_cents, remaining_cents,
            status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
        """,
        (
            receivable_id,
            data.receivable_no,
            data.agreement_id,
            data.operator_account_id,
            data.debtor,
            data.original_creditor_id,
            data.principal_cents,
            data.principal_cents,
            now,
        ),
    )
    conn.execute(
        """
        INSERT INTO receivable_holdings (
            holding_id, receivable_id, account_id, held_cents, updated_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (new_id("hold"), receivable_id, data.original_creditor_id, data.principal_cents, now),
    )
    # The settlement account exists independently of receivables; create it
    # lazily so queries always find the original creditor's account.
    _get_or_create_settlement_account(conn, data.original_creditor_id)

    row = _get_receivable_or_404(conn, receivable_id)
    result = _receivable_dict(row)
    result["holdings"] = _holdings_view(conn, receivable_id)
    return result


# ---------------------------------------------------------------------------
# Transfer application and confirmation
# ---------------------------------------------------------------------------


def _transfer_agreement_text(
    *,
    transfer_id: str,
    receivable_id: str,
    receivable_no: str,
    transferor_account_id: str,
    transferee_account_id: str,
    amount_cents: int,
) -> str:
    payload = {
        "schema": TRANSFER_AGREEMENT_SCHEMA,
        "transfer_id": transfer_id,
        "receivable_id": receivable_id,
        "receivable_no": receivable_no,
        "transferor_account_id": transferor_account_id,
        "transferee_account_id": transferee_account_id,
        "amount_cents": amount_cents,
        "currency": "simulated-single-currency",
        "amount_unit": "integer-minor-unit-cent",
        "created_at": utc_now(),
        "terms": (
            "转让人将其在本应收款项下尚未收回的部分本金转让给受让人；"
            "本协议仅在运营方依据已完成的本协议确认转让后生效，"
            "申请期间不冻结本金，债务人付款与退票按平台既有规则处理。"
        ),
    }
    return canonical_json_text(payload)


def apply_transfer_tx(conn: sqlite3.Connection, receivable_id: str, data: Any) -> dict[str, Any]:
    receivable = _get_receivable_or_404(conn, receivable_id)
    if data.transferor_account_id == data.transferee_account_id:
        raise ApiError(
            400, "SELF_TRANSFER", "Transferor and transferee must be different accounts."
        )
    _get_account_or_404(conn, data.transferor_account_id)
    _get_account_or_404(conn, data.transferee_account_id)

    holding = _holding_row(conn, receivable_id, data.transferor_account_id)
    held = holding["held_cents"] if holding is not None else 0
    if held <= 0:
        raise ApiError(
            409,
            "TRANSFEROR_HOLDS_NOTHING",
            "The transferor currently holds no unrecovered principal on this receivable.",
            {"receivable_id": receivable_id, "transferor_account_id": data.transferor_account_id},
        )
    if data.amount_cents > held:
        raise ApiError(
            409,
            "TRANSFER_AMOUNT_EXCEEDS_HOLDING",
            "The transfer amount exceeds the transferor's currently unrecovered principal.",
            {
                "amount_cents": data.amount_cents,
                "held_cents": held,
            },
        )

    transfer_id = new_id("trf")
    now = utc_now()
    content_text = _transfer_agreement_text(
        transfer_id=transfer_id,
        receivable_id=receivable_id,
        receivable_no=receivable["receivable_no"],
        transferor_account_id=data.transferor_account_id,
        transferee_account_id=data.transferee_account_id,
        amount_cents=data.amount_cents,
    )

    # Reuse the existing signing flow: create a two-seat, single-stage
    # agreement.  Both parties must sign through the normal challenge
    # endpoints before an operator can confirm the transfer.
    agreement_id = new_id("agr")
    conn.execute(
        """
        INSERT INTO agreements (
            agreement_id, initiator_account_id, title, content, content_sha256,
            status, created_at
        ) VALUES (?, ?, ?, ?, ?, 'draft', ?)
        """,
        (
            agreement_id,
            data.transferor_account_id,
            f"应收款本金转让协议 {receivable['receivable_no']}",
            content_text.encode("utf-8"),
            sha256_hex(content_text.encode("utf-8")),
            now,
        ),
    )
    for position, (seat_key, account_id) in enumerate(
        [
            ("transferor", data.transferor_account_id),
            ("transferee", data.transferee_account_id),
        ],
        start=1,
    ):
        conn.execute(
            """
            INSERT INTO seats (
                seat_id, agreement_id, seat_key, label, stage, position,
                original_account_id, status, current_account_id, authority_generation
            ) VALUES (?, ?, ?, ?, 1, ?, ?, 'pending', ?, 0)
            """,
            (
                new_id("seat"),
                agreement_id,
                seat_key,
                "转让人" if seat_key == "transferor" else "受让人",
                position,
                account_id,
                account_id,
            ),
        )
    # Make it immediately signable through the existing challenge flow.
    conn.execute(
        "UPDATE agreements SET status = 'active', sent_at = ? WHERE agreement_id = ?",
        (now, agreement_id),
    )

    conn.execute(
        """
        INSERT INTO transfer_applications (
            transfer_id, receivable_id, transferor_account_id,
            transferee_account_id, amount_cents, agreement_id, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            transfer_id,
            receivable_id,
            data.transferor_account_id,
            data.transferee_account_id,
            data.amount_cents,
            agreement_id,
            now,
        ),
    )

    return transfer_view(conn, transfer_id)


def confirm_transfer_tx(
    conn: sqlite3.Connection, transfer_id: str, data: Any
) -> OpResult:
    row = conn.execute(
        "SELECT * FROM transfer_applications WHERE transfer_id = ?", (transfer_id,)
    ).fetchone()
    if row is None:
        raise ApiError(
            404, "TRANSFER_NOT_FOUND", f"Transfer application {transfer_id!r} was not found."
        )
    _get_account_or_404(conn, data.operator_account_id)

    if row["status"] == "effective":
        raise ApiError(
            409,
            "TRANSFER_ALREADY_EFFECTIVE",
            "This transfer application has already taken effect; an application can take effect only once.",
            {"transfer_id": transfer_id},
        )
    if row["status"] == "terminated":
        raise ApiError(
            409,
            "TRANSFER_TERMINATED",
            "This transfer application was terminated and can never take effect, even after later refunds.",
            {"transfer_id": transfer_id, "terminated_reason": row["terminated_reason"]},
        )

    agreement = signing_service.get_agreement_or_404(conn, row["agreement_id"])
    if agreement["status"] != "completed":
        # Not fully signed yet: this is not a termination decision.  Nothing is
        # written, so a rolled-back error response is exactly right.
        raise ApiError(
            409,
            "TRANSFER_AGREEMENT_NOT_COMPLETED",
            "Only a fully completed transfer agreement can be confirmed; unsigned applications are not terminated.",
            {
                "transfer_id": transfer_id,
                "agreement_id": row["agreement_id"],
                "agreement_status": agreement["status"],
            },
        )

    now = utc_now()
    holding = _holding_row(conn, row["receivable_id"], row["transferor_account_id"])
    held = holding["held_cents"] if holding is not None else 0
    if held < row["amount_cents"]:
        # Whole transfer terminates.  No later refund revives it.  This is a
        # terminal business decision rather than a rejected write: the status
        # change must commit even though the HTTP response is a 409.  Raising
        # here would make the idempotency wrapper roll the decision back.
        conn.execute(
            """
            UPDATE transfer_applications
            SET status = 'terminated', terminated_reason = ?, terminated_at = ?
            WHERE transfer_id = ?
            """,
            (
                f"transferor unrecovered principal {held} < transfer amount {row['amount_cents']}",
                now,
                transfer_id,
            ),
        )
        view = transfer_view(conn, transfer_id)
        view["outcome"] = "terminated"
        view["error"] = {
            "code": "TRANSFER_INSUFFICIENT_PRINCIPAL",
            "message": (
                "The transferor's current unrecovered principal cannot cover the full "
                "transfer amount; the whole application is terminated and will not revive "
                "even if funds are later refunded."
            ),
            "details": {
                "transfer_id": transfer_id,
                "amount_cents": row["amount_cents"],
                "held_cents": held,
            },
        }
        return OpResult(409, view)

    # Move the principal between holdings.  Already booked allocations are not
    # moved; only the currently unrecovered slice changes ownership.
    _upsert_holding(
        conn, row["receivable_id"], row["transferor_account_id"], -row["amount_cents"]
    )
    _upsert_holding(
        conn, row["receivable_id"], row["transferee_account_id"], row["amount_cents"]
    )
    conn.execute(
        """
        UPDATE transfer_applications
        SET status = 'effective', effective_at = ?
        WHERE transfer_id = ? AND status = 'pending'
        """,
        (now, transfer_id),
    )
    if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
        # Defensive: the BEGIN IMMEDIATE serialization normally prevents this.
        raise ApiError(409, "TRANSFER_ALREADY_DECIDED", "Transfer was decided by another transaction.")

    return OpResult(200, transfer_view(conn, transfer_id))


def transfer_view(conn: sqlite3.Connection, transfer_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM transfer_applications WHERE transfer_id = ?", (transfer_id,)
    ).fetchone()
    if row is None:
        raise ApiError(
            404, "TRANSFER_NOT_FOUND", f"Transfer application {transfer_id!r} was not found."
        )
    agreement = signing_service.get_agreement_or_404(conn, row["agreement_id"])
    seats = signing_service.list_seats(conn, row["agreement_id"])
    signed = sum(1 for seat in seats if seat["status"] == "signed")
    return {
        "transfer_id": row["transfer_id"],
        "receivable_id": row["receivable_id"],
        "transferor_account_id": row["transferor_account_id"],
        "transferee_account_id": row["transferee_account_id"],
        "amount_cents": row["amount_cents"],
        "agreement_id": row["agreement_id"],
        "agreement_status": agreement["status"],
        "status": row["status"],
        "terminated_reason": row["terminated_reason"],
        "created_at": row["created_at"],
        "effective_at": row["effective_at"],
        "terminated_at": row["terminated_at"],
        "seat_count": len(seats),
        "signed_count": signed,
    }


# ---------------------------------------------------------------------------
# Receipt registration and largest-remainder allocation
# ---------------------------------------------------------------------------


def register_receipt_tx(
    conn: sqlite3.Connection, receivable_id: str, data: Any
) -> dict[str, Any]:
    receivable = _get_receivable_or_404(conn, receivable_id)
    _get_account_or_404(conn, data.operator_account_id)

    # Serial-number uniqueness is independent of the current balance: reusing
    # a serial with different content must always be rejected, even after the
    # receivable is fully recovered.
    serial_conflict = conn.execute(
        "SELECT * FROM receipts WHERE channel_serial_no = ?", (data.channel_serial_no,)
    ).fetchone()
    if serial_conflict is not None:
        raise ApiError(
            409,
            "CHANNEL_SERIAL_CONFLICT",
            "This channel serial number was already submitted for a receipt; "
            "reusing a serial number with different content is rejected.",
            {
                "channel_serial_no": data.channel_serial_no,
                "existing_receipt_id": serial_conflict["receipt_id"],
                "existing_amount_cents": serial_conflict["amount_cents"],
            },
        )

    if receivable["remaining_cents"] <= 0:
        raise ApiError(
            409,
            "RECEIVABLE_FULLY_RECOVERED",
            "No unrecovered principal remains on this receivable.",
            {"receivable_id": receivable_id},
        )
    if data.amount_cents > receivable["remaining_cents"]:
        raise ApiError(
            409,
            "RECEIPT_EXCEEDS_REMAINING",
            "The receipt amount exceeds the receivable's remaining principal.",
            {
                "amount_cents": data.amount_cents,
                "remaining_cents": receivable["remaining_cents"],
            },
        )

    holders = _holdings(conn, receivable_id)
    if not holders:
        raise ApiError(
            500,
            "NO_CREDITOR_HOLDINGS",
            "Receivable has remaining principal but no creditor holdings to allocate to.",
        )

    split_input = [(row["account_id"], row["held_cents"]) for row in holders]
    shares = largest_remainder_split(split_input, data.amount_cents)

    now = utc_now()
    receipt_id = new_id("rcpt")
    conn.execute(
        """
        INSERT INTO receipts (
            receipt_id, receivable_id, channel_serial_no, amount_cents,
            remaining_cents, operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            receipt_id,
            receivable_id,
            data.channel_serial_no,
            data.amount_cents,
            data.amount_cents,
            data.operator_account_id,
            now,
        ),
    )

    allocations: list[dict[str, Any]] = []
    for position, (account_id, share) in enumerate(shares):
        if share <= 0:
            continue
        allocation_id = new_id("alloc")
        # The corresponding slice of principal is treated as recovered.
        _upsert_holding(conn, receivable_id, account_id, -share)
        net_credited = _credit_allocation(conn, account_id, share, allocation_id)
        deduction_offset = share - net_credited
        conn.execute(
            """
            INSERT INTO receipt_allocations (
                allocation_id, receipt_id, account_id, amount_cents,
                reversed_cents, deduction_offset_cents, net_credited_cents,
                position, created_at
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                allocation_id,
                receipt_id,
                account_id,
                share,
                deduction_offset,
                net_credited,
                position,
                now,
            ),
        )
        allocations.append(
            {
                "allocation_id": allocation_id,
                "receipt_id": receipt_id,
                "account_id": account_id,
                "position": position,
                "amount_cents": share,
                "reversed_cents": 0,
                "deduction_offset_cents": deduction_offset,
                "net_credited_cents": net_credited,
            }
        )

    new_remaining = receivable["remaining_cents"] - data.amount_cents
    conn.execute(
        """
        UPDATE receivables
        SET remaining_cents = ?,
            status = CASE WHEN ? = 0 THEN 'settled' ELSE status END
        WHERE receivable_id = ?
        """,
        (new_remaining, new_remaining, receivable_id),
    )

    return receipt_detail(conn, receipt_id)


# ---------------------------------------------------------------------------
# Refund registration and original-line clawback
# ---------------------------------------------------------------------------


def register_refund_tx(
    conn: sqlite3.Connection, receipt_id: str, data: Any
) -> dict[str, Any]:
    receipt = conn.execute(
        "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
    ).fetchone()
    if receipt is None:
        raise ApiError(
            404, "RECEIPT_NOT_FOUND", f"Receipt {receipt_id!r} was not found."
        )
    _get_account_or_404(conn, data.operator_account_id)

    serial_conflict = conn.execute(
        "SELECT * FROM refunds WHERE channel_serial_no = ?", (data.channel_serial_no,)
    ).fetchone()
    if serial_conflict is not None:
        raise ApiError(
            409,
            "CHANNEL_SERIAL_CONFLICT",
            "This channel serial number was already submitted for a refund; "
            "reusing a serial number with different content is rejected.",
            {
                "channel_serial_no": data.channel_serial_no,
                "existing_refund_id": serial_conflict["refund_id"],
                "existing_amount_cents": serial_conflict["amount_cents"],
            },
        )

    already_refunded = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) AS total FROM refunds WHERE receipt_id = ?",
        (receipt_id,),
    ).fetchone()["total"]
    available_to_refund = receipt["amount_cents"] - already_refunded
    if data.amount_cents > available_to_refund:
        raise ApiError(
            409,
            "REFUND_EXCEEDS_RECEIPT",
            "Cumulative refunds cannot exceed the original receipt amount.",
            {
                "refund_amount_cents": data.amount_cents,
                "already_refunded_cents": already_refunded,
                "receipt_amount_cents": receipt["amount_cents"],
                "available_to_refund_cents": available_to_refund,
            },
        )

    # Reverse against the ORIGINAL split lines: amount descending, ties by
    # account id ascending.  Only the not-yet-reversed portion participates.
    lines = list(
        conn.execute(
            """
            SELECT * FROM receipt_allocations
            WHERE receipt_id = ? AND amount_cents - reversed_cents > 0
            ORDER BY amount_cents DESC, account_id ASC
            """,
            (receipt_id,),
        ).fetchall()
    )

    now = utc_now()
    refund_id = new_id("rfnd")
    conn.execute(
        """
        INSERT INTO refunds (
            refund_id, receipt_id, channel_serial_no, amount_cents,
            operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            refund_id,
            receipt_id,
            data.channel_serial_no,
            data.amount_cents,
            data.operator_account_id,
            now,
        ),
    )

    remaining_to_reverse = data.amount_cents
    reversals: list[dict[str, Any]] = []
    for position, line in enumerate(lines):
        if remaining_to_reverse <= 0:
            break
        reversible = line["amount_cents"] - line["reversed_cents"]
        take = min(reversible, remaining_to_reverse)
        reversal_id = new_id("rvrs")
        from_balance, to_deduction = _clawback(
            conn, line["account_id"], take, reversal_id
        )
        conn.execute(
            """
            INSERT INTO refund_reversals (
                reversal_id, refund_id, allocation_id, account_id, amount_cents,
                clawback_from_balance, clawback_to_deduction, position, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reversal_id,
                refund_id,
                line["allocation_id"],
                line["account_id"],
                take,
                from_balance,
                to_deduction,
                position,
                now,
            ),
        )
        conn.execute(
            """
            UPDATE receipt_allocations
            SET reversed_cents = reversed_cents + ?
            WHERE allocation_id = ?
            """,
            (take, line["allocation_id"]),
        )
        # Principal is restored to the original payee's holding, not
        # recomputed by current creditor ratios.
        _upsert_holding(conn, receipt["receivable_id"], line["account_id"], take)
        remaining_to_reverse -= take
        reversals.append(
            {
                "reversal_id": reversal_id,
                "refund_id": refund_id,
                "allocation_id": line["allocation_id"],
                "account_id": line["account_id"],
                "position": position,
                "amount_cents": take,
                "clawback_from_balance_cents": from_balance,
                "clawback_to_deduction_cents": to_deduction,
            }
        )

    if remaining_to_reverse != 0:
        # Should be impossible given the cumulative cap; guard the invariant.
        raise ApiError(500, "REFUND_ALLOCATION_MISMATCH", "Refund could not be fully reversed.")

    conn.execute(
        "UPDATE receipts SET remaining_cents = remaining_cents - ? WHERE receipt_id = ?",
        (data.amount_cents, receipt_id),
    )
    receivable = _get_receivable_or_404(conn, receipt["receivable_id"])
    restored_remaining = receivable["remaining_cents"] + data.amount_cents
    conn.execute(
        """
        UPDATE receivables
        SET remaining_cents = ?, status = 'open'
        WHERE receivable_id = ?
        """,
        (restored_remaining, receipt["receivable_id"]),
    )

    return refund_detail(conn, refund_id)


# ---------------------------------------------------------------------------
# Disbursements
# ---------------------------------------------------------------------------


def register_disbursement_tx(conn: sqlite3.Connection, data: Any) -> dict[str, Any]:
    _get_account_or_404(conn, data.account_id)
    _get_account_or_404(conn, data.operator_account_id)
    account = _get_or_create_settlement_account(conn, data.account_id)

    if data.amount_cents > account["available_cents"]:
        raise ApiError(
            409,
            "INSUFFICIENT_AVAILABLE_BALANCE",
            "The disbursement cannot exceed the account's drawable balance.",
            {
                "account_id": data.account_id,
                "amount_cents": data.amount_cents,
                "available_cents": account["available_cents"],
            },
        )

    now = utc_now()
    disbursement_id = new_id("dsb")
    conn.execute(
        """
        INSERT INTO disbursements (
            disbursement_id, account_id, amount_cents, note,
            operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            disbursement_id,
            data.account_id,
            data.amount_cents,
            data.note,
            data.operator_account_id,
            now,
        ),
    )
    conn.execute(
        """
        UPDATE settlement_accounts
        SET available_cents = available_cents - ?,
            total_disbursed_cents = total_disbursed_cents + ?,
            updated_at = ?
        WHERE account_id = ?
        """,
        (data.amount_cents, data.amount_cents, now, data.account_id),
    )
    _ledger(
        conn,
        data.account_id,
        "disbursement",
        "disbursement",
        disbursement_id,
        -data.amount_cents,
        0,
    )
    return {
        "disbursement_id": disbursement_id,
        "account_id": data.account_id,
        "amount_cents": data.amount_cents,
        "note": data.note,
        "operator_account_id": data.operator_account_id,
        "created_at": now,
        "settlement_account": settlement_account_view(conn, data.account_id),
    }


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


def _holdings_view(conn: sqlite3.Connection, receivable_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM receivable_holdings
        WHERE receivable_id = ?
        ORDER BY account_id ASC
        """,
        (receivable_id,),
    ).fetchall()
    return [
        {
            "holding_id": row["holding_id"],
            "account_id": row["account_id"],
            "held_cents": row["held_cents"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def receivable_detail(conn: sqlite3.Connection, receivable_id: str) -> dict[str, Any]:
    row = _get_receivable_or_404(conn, receivable_id)
    result = _receivable_dict(row)
    result["holdings"] = _holdings_view(conn, receivable_id)

    transfers = conn.execute(
        "SELECT transfer_id FROM transfer_applications WHERE receivable_id = ? ORDER BY rowid",
        (receivable_id,),
    ).fetchall()
    result["transfer_ids"] = [row["transfer_id"] for row in transfers]

    receipts = conn.execute(
        "SELECT receipt_id FROM receipts WHERE receivable_id = ? ORDER BY rowid",
        (receivable_id,),
    ).fetchall()
    result["receipt_ids"] = [row["receipt_id"] for row in receipts]
    return result


def list_receivables(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT * FROM receivables
        ORDER BY created_at DESC, rowid DESC
        """
    ).fetchall()
    return {"receivables": [_receivable_dict(row) for row in rows]}


def receipt_detail(conn: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
    ).fetchone()
    if row is None:
        raise ApiError(404, "RECEIPT_NOT_FOUND", f"Receipt {receipt_id!r} was not found.")

    allocations = list(
        conn.execute(
            """
            SELECT * FROM receipt_allocations
            WHERE receipt_id = ?
            ORDER BY position ASC, rowid ASC
            """,
            (receipt_id,),
        ).fetchall()
    )
    refunds = list(
        conn.execute(
            "SELECT * FROM refunds WHERE receipt_id = ? ORDER BY rowid ASC", (receipt_id,)
        ).fetchall()
    )
    refunded_total = sum(item["amount_cents"] for item in refunds)
    return {
        "receipt_id": row["receipt_id"],
        "receivable_id": row["receivable_id"],
        "channel_serial_no": row["channel_serial_no"],
        "amount_cents": row["amount_cents"],
        "remaining_cents": row["remaining_cents"],
        "refunded_cents": refunded_total,
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "allocations": [
            {
                "allocation_id": item["allocation_id"],
                "account_id": item["account_id"],
                "position": item["position"],
                "amount_cents": item["amount_cents"],
                "reversed_cents": item["reversed_cents"],
                "unreversed_cents": item["amount_cents"] - item["reversed_cents"],
                "deduction_offset_cents": item["deduction_offset_cents"],
                "net_credited_cents": item["net_credited_cents"],
            }
            for item in allocations
        ],
        "refund_ids": [item["refund_id"] for item in refunds],
    }


def refund_detail(conn: sqlite3.Connection, refund_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM refunds WHERE refund_id = ?", (refund_id,)
    ).fetchone()
    if row is None:
        raise ApiError(404, "REFUND_NOT_FOUND", f"Refund {refund_id!r} was not found.")
    reversals = list(
        conn.execute(
            """
            SELECT * FROM refund_reversals
            WHERE refund_id = ?
            ORDER BY position ASC, rowid ASC
            """,
            (refund_id,),
        ).fetchall()
    )
    return {
        "refund_id": row["refund_id"],
        "receipt_id": row["receipt_id"],
        "channel_serial_no": row["channel_serial_no"],
        "amount_cents": row["amount_cents"],
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "reversals": [
            {
                "reversal_id": item["reversal_id"],
                "allocation_id": item["allocation_id"],
                "account_id": item["account_id"],
                "position": item["position"],
                "amount_cents": item["amount_cents"],
                "clawback_from_balance_cents": item["clawback_from_balance"],
                "clawback_to_deduction_cents": item["clawback_to_deduction"],
            }
            for item in reversals
        ],
    }


def list_transfers(conn: sqlite3.Connection, receivable_id: Optional[str] = None) -> dict[str, Any]:
    if receivable_id is not None:
        _get_receivable_or_404(conn, receivable_id)
        rows = conn.execute(
            "SELECT transfer_id FROM transfer_applications WHERE receivable_id = ? ORDER BY rowid",
            (receivable_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT transfer_id FROM transfer_applications ORDER BY rowid"
        ).fetchall()
    return {
        "transfers": [transfer_view(conn, row["transfer_id"]) for row in rows]
    }


def settlement_account_view(conn: sqlite3.Connection, account_id: str) -> dict[str, Any]:
    _get_account_or_404(conn, account_id)
    row = _get_or_create_settlement_account(conn, account_id)
    disbursements = list(
        conn.execute(
            "SELECT * FROM disbursements WHERE account_id = ? ORDER BY rowid ASC",
            (account_id,),
        ).fetchall()
    )
    ledger = list(
        conn.execute(
            "SELECT * FROM settlement_ledger WHERE account_id = ? ORDER BY rowid ASC",
            (account_id,),
        ).fetchall()
    )
    return {
        "account_id": account_id,
        "available_cents": row["available_cents"],
        "pending_deduction_cents": row["pending_deduction_cents"],
        "total_allocated_cents": row["total_allocated_cents"],
        "total_clawback_cents": row["total_clawback_cents"],
        "total_disbursed_cents": row["total_disbursed_cents"],
        "updated_at": row["updated_at"],
        "disbursements": [
            {
                "disbursement_id": item["disbursement_id"],
                "amount_cents": item["amount_cents"],
                "note": item["note"],
                "operator_account_id": item["operator_account_id"],
                "created_at": item["created_at"],
            }
            for item in disbursements
        ],
        "ledger": [
            {
                "ledger_id": item["ledger_id"],
                "event_type": item["event_type"],
                "ref_type": item["ref_type"],
                "ref_id": item["ref_id"],
                "delta_available": item["delta_available"],
                "delta_deduction": item["delta_deduction"],
                "balance_after": item["balance_after"],
                "deduction_after": item["deduction_after"],
                "created_at": item["created_at"],
            }
            for item in ledger
        ],
    }


def list_settlement_accounts(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT account_id FROM settlement_accounts ORDER BY account_id ASC"
    ).fetchall()
    return {
        "accounts": [
            settlement_account_view(conn, row["account_id"]) for row in rows
        ]
    }
