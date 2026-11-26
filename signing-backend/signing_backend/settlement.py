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
    *,
    ref_type: str = "receipt_allocation",
    credit_event_type: str = "allocation",
    offset_event_type: str = "allocation_deduction_offset",
) -> int:
    """Credit gross funds to an account, absorbing any clawback debt first.

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
        credit_event_type,
        ref_type,
        allocation_id,
        net,
        0,
    )
    if offset:
        _ledger(
            conn,
            account_id,
            offset_event_type,
            ref_type,
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
# Guarantee funds
# ---------------------------------------------------------------------------


def _get_fund_or_404(conn: sqlite3.Connection, fund_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM guarantee_funds WHERE fund_id = ?", (fund_id,)
    ).fetchone()
    if row is None:
        raise ApiError(404, "GUARANTEE_FUND_NOT_FOUND", f"Guarantee fund {fund_id!r} was not found.")
    return row


def _validate_optional_operator(
    conn: sqlite3.Connection, operator_account_id: Optional[str]
) -> None:
    if operator_account_id:
        _get_account_or_404(conn, operator_account_id)


def _fund_ledger(
    conn: sqlite3.Connection,
    fund_id: str,
    event_type: str,
    ref_type: str,
    ref_id: str,
    gross_cents: int,
    delta_available: int,
    delta_gap: int,
) -> None:
    fund = _get_fund_or_404(conn, fund_id)
    conn.execute(
        """
        INSERT INTO fund_ledger (
            ledger_id, fund_id, event_type, ref_type, ref_id, gross_cents,
            delta_available, delta_gap, available_after, gap_after, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id("fled"),
            fund_id,
            event_type,
            ref_type,
            ref_id,
            gross_cents,
            delta_available,
            delta_gap,
            fund["available_cents"],
            fund["gap_cents"],
            utc_now(),
        ),
    )


def _fund_apply_inflow(
    conn: sqlite3.Connection,
    fund_id: str,
    amount_cents: int,
    *,
    event_type: str,
    ref_type: str,
    ref_id: str,
    total_column: str,
) -> tuple[int, int]:
    """Add contribution/recovery money, always curing gap first.

    Returns ``(gap_offset_cents, available_credited_cents)``.
    """
    if amount_cents <= 0:
        raise ApiError(500, "FUND_INFLOW_INVALID", "Fund inflow must be positive.")
    fund = _get_fund_or_404(conn, fund_id)
    gap_offset = min(fund["gap_cents"], amount_cents)
    available_credit = amount_cents - gap_offset
    now = utc_now()
    # total_column is chosen by internal callers, never request input.
    conn.execute(
        f"""
        UPDATE guarantee_funds
        SET available_cents = available_cents + ?,
            gap_cents = gap_cents - ?,
            {total_column} = {total_column} + ?,
            updated_at = ?
        WHERE fund_id = ?
        """,  # noqa: S608 - fixed internal column names
        (available_credit, gap_offset, amount_cents, now, fund_id),
    )
    _fund_ledger(
        conn,
        fund_id,
        event_type,
        ref_type,
        ref_id,
        amount_cents,
        available_credit,
        -gap_offset,
    )
    return gap_offset, available_credit


def _fund_spend_compensation(
    conn: sqlite3.Connection, fund_id: str, amount_cents: int, compensation_id: str
) -> None:
    fund = _get_fund_or_404(conn, fund_id)
    if fund["gap_cents"] > 0:
        raise ApiError(
            409,
            "GUARANTEE_FUND_GAP_OUTSTANDING",
            "The guarantee fund has an outstanding refund gap; new compensation is blocked until it is fully cured.",
            {"fund_id": fund_id, "gap_cents": fund["gap_cents"]},
        )
    if amount_cents > fund["available_cents"]:
        raise ApiError(
            409,
            "GUARANTEE_FUND_INSUFFICIENT",
            "The compensation amount exceeds the fund's available funds.",
            {
                "fund_id": fund_id,
                "amount_cents": amount_cents,
                "available_cents": fund["available_cents"],
            },
        )
    now = utc_now()
    conn.execute(
        """
        UPDATE guarantee_funds
        SET available_cents = available_cents - ?,
            total_compensation_cents = total_compensation_cents + ?,
            updated_at = ?
        WHERE fund_id = ?
        """,
        (amount_cents, amount_cents, now, fund_id),
    )
    _fund_ledger(
        conn,
        fund_id,
        "compensation",
        "guarantee_compensation",
        compensation_id,
        amount_cents,
        -amount_cents,
        0,
    )


def _fund_deduct_refund(
    conn: sqlite3.Connection,
    fund_id: str,
    amount_cents: int,
    reversal_id: str,
) -> tuple[int, int]:
    """Deduct a reversed recovery from its current fund.

    Money already reused for another compensation is never clawed back from
    that compensation.  Insufficient fund cash becomes a fund gap.
    """
    fund = _get_fund_or_404(conn, fund_id)
    from_available = min(fund["available_cents"], amount_cents)
    gap_added = amount_cents - from_available
    now = utc_now()
    conn.execute(
        """
        UPDATE guarantee_funds
        SET available_cents = available_cents - ?,
            gap_cents = gap_cents + ?,
            total_refund_clawback_cents = total_refund_clawback_cents + ?,
            updated_at = ?
        WHERE fund_id = ?
        """,
        (from_available, gap_added, amount_cents, now, fund_id),
    )
    _fund_ledger(
        conn,
        fund_id,
        "refund_clawback",
        "refund_guarantee_reversal",
        reversal_id,
        amount_cents,
        -from_available,
        gap_added,
    )
    return from_available, gap_added


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
# Guarantee fund creation, funding, binding and compensation batches
# ---------------------------------------------------------------------------


def create_guarantee_fund_tx(conn: sqlite3.Connection, data: Any) -> dict[str, Any]:
    _validate_optional_operator(conn, data.operator_account_id)

    fund_id = data.fund_id or new_id("fund")
    fund_no = data.fund_no or getattr(data, "fund_code", None) or getattr(data, "code", None) or fund_id
    existing_id = conn.execute(
        "SELECT fund_id FROM guarantee_funds WHERE fund_id = ?", (fund_id,)
    ).fetchone()
    if existing_id is not None:
        raise ApiError(
            409,
            "GUARANTEE_FUND_ID_CONFLICT",
            "A guarantee fund with this fund_id already exists.",
            {"fund_id": fund_id},
        )
    existing_no = conn.execute(
        "SELECT fund_id FROM guarantee_funds WHERE fund_no = ?", (fund_no,)
    ).fetchone()
    if existing_no is not None:
        raise ApiError(
            409,
            "GUARANTEE_FUND_NO_CONFLICT",
            "A guarantee fund with this fund_no already exists.",
            {"fund_no": fund_no, "fund_id": existing_no["fund_id"]},
        )

    now = utc_now()
    conn.execute(
        """
        INSERT INTO guarantee_funds (
            fund_id, fund_no, name, available_cents, gap_cents,
            total_contribution_cents, total_compensation_cents,
            total_recovery_cents, total_refund_clawback_cents,
            operator_account_id, created_at, updated_at
        ) VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, ?)
        """,
        (
            fund_id,
            fund_no,
            data.resolved_name,
            data.operator_account_id,
            now,
            now,
        ),
    )

    initial_amount = data.resolved_initial_amount_cents
    if initial_amount > 0:
        contribution_id = new_id("fcontrib")
        conn.execute(
            """
            INSERT INTO fund_contributions (
                contribution_id, fund_id, amount_cents, note,
                operator_account_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                contribution_id,
                fund_id,
                initial_amount,
                "initial contribution",
                data.operator_account_id,
                now,
            ),
        )
        _fund_apply_inflow(
            conn,
            fund_id,
            initial_amount,
            event_type="contribution",
            ref_type="fund_contribution",
            ref_id=contribution_id,
            total_column="total_contribution_cents",
        )

    return guarantee_fund_view(conn, fund_id)


def register_fund_contribution_tx(
    conn: sqlite3.Connection, fund_id: str, data: Any
) -> dict[str, Any]:
    _get_fund_or_404(conn, fund_id)
    _validate_optional_operator(conn, data.operator_account_id)

    contribution_id = new_id("fcontrib")
    now = utc_now()
    conn.execute(
        """
        INSERT INTO fund_contributions (
            contribution_id, fund_id, amount_cents, note,
            operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            contribution_id,
            fund_id,
            data.amount_cents,
            data.note,
            data.operator_account_id,
            now,
        ),
    )
    gap_offset, available_credited = _fund_apply_inflow(
        conn,
        fund_id,
        data.amount_cents,
        event_type="contribution",
        ref_type="fund_contribution",
        ref_id=contribution_id,
        total_column="total_contribution_cents",
    )
    return {
        "id": contribution_id,
        "contribution_id": contribution_id,
        "fund_id": fund_id,
        "amount_cents": data.amount_cents,
        "gap_offset_cents": gap_offset,
        "available_credited_cents": available_credited,
        "note": data.note,
        "operator_account_id": data.operator_account_id,
        "created_at": now,
        "fund": guarantee_fund_view(conn, fund_id),
    }


def _binding_by_receivable(
    conn: sqlite3.Connection, receivable_id: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM receivable_fund_bindings WHERE receivable_id = ?",
        (receivable_id,),
    ).fetchone()


def _outstanding_compensation_cents(
    conn: sqlite3.Connection, receivable_id: str
) -> int:
    row = conn.execute(
        """
        SELECT COALESCE(SUM(amount_cents - recovered_cents), 0) AS total
        FROM guarantee_compensations
        WHERE receivable_id = ?
        """,
        (receivable_id,),
    ).fetchone()
    return int(row["total"])


def bind_receivable_fund_tx(
    conn: sqlite3.Connection, receivable_id: str, data: Any
) -> dict[str, Any]:
    _get_receivable_or_404(conn, receivable_id)
    _get_fund_or_404(conn, data.fund_id)
    _validate_optional_operator(conn, data.operator_account_id)

    existing = _binding_by_receivable(conn, receivable_id)
    if existing is not None:
        raise ApiError(
            409,
            "RECEIVABLE_FUND_ALREADY_BOUND",
            "A receivable can be bound to only one guarantee fund.",
            {
                "receivable_id": receivable_id,
                "existing_fund_id": existing["fund_id"],
                "binding_id": existing["binding_id"],
            },
        )

    limit_cents = data.resolved_limit_cents
    if limit_cents <= 0:
        raise ApiError(400, "INVALID_COMPENSATION_LIMIT", "Compensation limit must be positive.")

    binding_id = new_id("bind")
    now = utc_now()
    conn.execute(
        """
        INSERT INTO receivable_fund_bindings (
            binding_id, receivable_id, fund_id, compensation_limit_cents,
            operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            binding_id,
            receivable_id,
            data.fund_id,
            limit_cents,
            data.operator_account_id,
            now,
        ),
    )
    return guarantee_binding_view(conn, binding_id)


def register_compensation_tx(
    conn: sqlite3.Connection, receivable_id: str, data: Any
) -> dict[str, Any]:
    # A top-level /compensations route may carry the receivable id in the body.
    receivable_id = receivable_id or getattr(data, "receivable_id", None)
    if not receivable_id:
        raise ApiError(400, "MISSING_RECEIVABLE_ID", "receivable_id is required.")

    receivable = _get_receivable_or_404(conn, receivable_id)
    binding = _binding_by_receivable(conn, receivable_id)
    if binding is None:
        raise ApiError(
            409,
            "RECEIVABLE_FUND_NOT_BOUND",
            "Bind this receivable to a guarantee fund before registering compensation.",
            {"receivable_id": receivable_id},
        )

    fund_id = getattr(data, "fund_id", None) or binding["fund_id"]
    if fund_id != binding["fund_id"]:
        raise ApiError(
            409,
            "COMPENSATION_FUND_MISMATCH",
            "The specified fund does not match the receivable's bound guarantee fund.",
            {"receivable_id": receivable_id, "bound_fund_id": binding["fund_id"], "fund_id": fund_id},
        )
    fund = _get_fund_or_404(conn, fund_id)
    _validate_optional_operator(conn, getattr(data, "operator_account_id", None))

    creditor_account_id = data.resolved_creditor_account_id
    _get_account_or_404(conn, creditor_account_id)

    holding = _holding_row(conn, receivable_id, creditor_account_id)
    ordinary_held = int(holding["held_cents"]) if holding is not None else 0
    if data.amount_cents > ordinary_held:
        raise ApiError(
            409,
            "COMPENSATION_EXCEEDS_ORDINARY_PRINCIPAL",
            "Compensation must be within the creditor's current ordinary unrecovered principal.",
            {
                "receivable_id": receivable_id,
                "creditor_account_id": creditor_account_id,
                "amount_cents": data.amount_cents,
                "ordinary_unrecovered_cents": ordinary_held,
            },
        )

    outstanding = _outstanding_compensation_cents(conn, receivable_id)
    limit_cents = int(binding["compensation_limit_cents"])
    # headroom is max(0, limit-outstanding); an over-limit refund leaves the
    # signed headroom negative and therefore blocks every new positive comp.
    signed_headroom = limit_cents - outstanding
    if data.amount_cents > signed_headroom:
        raise ApiError(
            409,
            "COMPENSATION_LIMIT_EXCEEDED",
            "Compensation must fit in the receivable's remaining guarantee limit.",
            {
                "receivable_id": receivable_id,
                "amount_cents": data.amount_cents,
                "limit_cents": limit_cents,
                "outstanding_compensation_cents": outstanding,
                "remaining_limit_cents": max(0, signed_headroom),
                "limit_headroom_cents": signed_headroom,
            },
        )

    if fund["gap_cents"] > 0:
        raise ApiError(
            409,
            "GUARANTEE_FUND_GAP_OUTSTANDING",
            "The fund has an outstanding gap; new compensation is blocked until contributions or recoveries cure it.",
            {"fund_id": fund_id, "gap_cents": fund["gap_cents"]},
        )
    if data.amount_cents > fund["available_cents"]:
        raise ApiError(
            409,
            "GUARANTEE_FUND_INSUFFICIENT",
            "Compensation must fit within the fund's available funds.",
            {
                "fund_id": fund_id,
                "amount_cents": data.amount_cents,
                "available_cents": fund["available_cents"],
            },
        )

    seq_row = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM guarantee_compensations WHERE receivable_id = ?",
        (receivable_id,),
    ).fetchone()
    seq = int(seq_row["next_seq"])
    compensation_id = new_id("gcomp")
    now = utc_now()

    # Conversion of ordinary principal into a subrogation batch.  This is not
    # a debtor payment: receivables.remaining_cents is intentionally unchanged.
    _upsert_holding(conn, receivable_id, creditor_account_id, -data.amount_cents)
    conn.execute(
        """
        INSERT INTO guarantee_compensations (
            compensation_id, receivable_id, fund_id, creditor_account_id, seq,
            amount_cents, recovered_cents, deduction_offset_cents,
            net_credited_cents, operator_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
        """,
        (
            compensation_id,
            receivable_id,
            fund_id,
            creditor_account_id,
            seq,
            data.amount_cents,
            getattr(data, "operator_account_id", None),
            now,
        ),
    )

    # Fund cash leaves available; creditor settlement account is credited with
    # the usual pending-deduction-first rule.
    _fund_spend_compensation(conn, fund_id, data.amount_cents, compensation_id)
    net_credited = _credit_allocation(
        conn,
        creditor_account_id,
        data.amount_cents,
        compensation_id,
        ref_type="guarantee_compensation",
        credit_event_type="guarantee_compensation_credit",
        offset_event_type="guarantee_compensation_offset",
    )
    deduction_offset = data.amount_cents - net_credited
    conn.execute(
        """
        UPDATE guarantee_compensations
        SET deduction_offset_cents = ?, net_credited_cents = ?
        WHERE compensation_id = ?
        """,
        (deduction_offset, net_credited, compensation_id),
    )

    return compensation_view(conn, compensation_id)


# ---------------------------------------------------------------------------
# Receipt registration and largest-remainder allocation
# ---------------------------------------------------------------------------


def _register_bound_receipt_tx(
    conn: sqlite3.Connection,
    receivable_id: str,
    data: Any,
    receivable: sqlite3.Row,
) -> dict[str, Any]:
    """Allocate a receipt on a bound receivable.

    Outstanding compensation batches are recovered first in compensation
    order and money goes to their funds.  Only the remainder is split among
    current ordinary creditor holdings.
    """
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

    batches = list(
        conn.execute(
            """
            SELECT * FROM guarantee_compensations
            WHERE receivable_id = ? AND amount_cents - recovered_cents > 0
            ORDER BY seq ASC, rowid ASC
            """,
            (receivable_id,),
        ).fetchall()
    )

    amount_left = data.amount_cents
    batch_plan: list[tuple[sqlite3.Row, int]] = []
    for batch in batches:
        if amount_left <= 0:
            break
        outstanding = batch["amount_cents"] - batch["recovered_cents"]
        take = min(outstanding, amount_left)
        if take > 0:
            batch_plan.append((batch, take))
            amount_left -= take

    ordinary_amount = amount_left
    holders = _holdings(conn, receivable_id) if ordinary_amount > 0 else []
    if ordinary_amount > 0:
        if not holders:
            raise ApiError(
                500,
                "NO_ORDINARY_HOLDINGS",
                "Receipt remainder has no ordinary creditor holdings to allocate to.",
            )
        ordinary_shares = largest_remainder_split(
            [(row["account_id"], row["held_cents"]) for row in holders],
            ordinary_amount,
        )
    else:
        ordinary_shares = []

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

    for position, (batch, take) in enumerate(batch_plan):
        guarantee_allocation_id = new_id("galloc")
        gap_offset, available_credited = _fund_apply_inflow(
            conn,
            batch["fund_id"],
            take,
            event_type="recovery",
            ref_type="receipt_guarantee_allocation",
            ref_id=guarantee_allocation_id,
            total_column="total_recovery_cents",
        )
        conn.execute(
            """
            UPDATE guarantee_compensations
            SET recovered_cents = recovered_cents + ?
            WHERE compensation_id = ?
            """,
            (take, batch["compensation_id"]),
        )
        conn.execute(
            """
            INSERT INTO receipt_guarantee_allocations (
                allocation_id, receipt_id, compensation_id, fund_id, position,
                amount_cents, reversed_cents, gap_offset_cents,
                available_credited_cents, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                guarantee_allocation_id,
                receipt_id,
                batch["compensation_id"],
                batch["fund_id"],
                position,
                take,
                gap_offset,
                available_credited,
                now,
            ),
        )

    for position, (account_id, share) in enumerate(ordinary_shares):
        if share <= 0:
            continue
        allocation_id = new_id("alloc")
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

    if _binding_by_receivable(conn, receivable_id) is not None:
        return _register_bound_receipt_tx(conn, receivable_id, data, receivable)

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

    has_guarantee_slice = conn.execute(
        "SELECT 1 FROM receipt_guarantee_allocations WHERE receipt_id = ? LIMIT 1",
        (receipt_id,),
    ).fetchone()
    if has_guarantee_slice is not None:
        return _register_guarantee_refund_tx(conn, receipt, data)

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


def _register_guarantee_refund_tx(
    conn: sqlite3.Connection, receipt: sqlite3.Row, data: Any
) -> dict[str, Any]:
    """Reverse a bound-receivable receipt in the mandated priority order.

    Ordinary creditor lines are reversed first using the legacy original-line
    order.  Only then are fund/batch slices reversed, in reverse FIFO batch
    order for this receipt.  Fund insufficiency becomes a fund gap rather than
    undoing any later compensation.
    """
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
            receipt["receipt_id"],
            data.channel_serial_no,
            data.amount_cents,
            data.operator_account_id,
            now,
        ),
    )

    remaining_to_reverse = data.amount_cents
    position = 0

    # Phase 1: ordinary distributions, unchanged original-line ordering.
    ordinary_lines = list(
        conn.execute(
            """
            SELECT * FROM receipt_allocations
            WHERE receipt_id = ? AND amount_cents - reversed_cents > 0
            ORDER BY amount_cents DESC, account_id ASC
            """,
            (receipt["receipt_id"],),
        ).fetchall()
    )
    for line in ordinary_lines:
        if remaining_to_reverse <= 0:
            break
        take = min(line["amount_cents"] - line["reversed_cents"], remaining_to_reverse)
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
            "UPDATE receipt_allocations SET reversed_cents = reversed_cents + ? WHERE allocation_id = ?",
            (take, line["allocation_id"]),
        )
        _upsert_holding(conn, receipt["receivable_id"], line["account_id"], take)
        remaining_to_reverse -= take
        position += 1

    # Phase 2: fund slices, reverse of the batch FIFO order used by this receipt.
    guarantee_lines = list(
        conn.execute(
            """
            SELECT * FROM receipt_guarantee_allocations
            WHERE receipt_id = ? AND amount_cents - reversed_cents > 0
            ORDER BY position DESC, rowid DESC
            """,
            (receipt["receipt_id"],),
        ).fetchall()
    )
    for line in guarantee_lines:
        if remaining_to_reverse <= 0:
            break
        take = min(line["amount_cents"] - line["reversed_cents"], remaining_to_reverse)
        reversal_id = new_id("grvrs")
        deducted_available, gap_added = _fund_deduct_refund(
            conn, line["fund_id"], take, reversal_id
        )
        conn.execute(
            """
            INSERT INTO refund_guarantee_reversals (
                reversal_id, refund_id, guarantee_allocation_id,
                compensation_id, fund_id, position, amount_cents,
                deducted_available_cents, gap_added_cents, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reversal_id,
                refund_id,
                line["allocation_id"],
                line["compensation_id"],
                line["fund_id"],
                position,
                take,
                deducted_available,
                gap_added,
                now,
            ),
        )
        conn.execute(
            """
            UPDATE receipt_guarantee_allocations
            SET reversed_cents = reversed_cents + ?
            WHERE allocation_id = ?
            """,
            (take, line["allocation_id"]),
        )
        # Restore the batch's subrogation principal/balance.  A resulting
        # receivable compensation total above the binding limit is allowed.
        conn.execute(
            """
            UPDATE guarantee_compensations
            SET recovered_cents = recovered_cents - ?
            WHERE compensation_id = ? AND recovered_cents >= ?
            """,
            (take, line["compensation_id"], take),
        )
        if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
            raise ApiError(
                500,
                "COMPENSATION_REVERSAL_MISMATCH",
                "Could not restore the reversed compensation batch principal.",
            )
        remaining_to_reverse -= take
        position += 1

    if remaining_to_reverse != 0:
        raise ApiError(500, "REFUND_ALLOCATION_MISMATCH", "Refund could not be fully reversed.")

    conn.execute(
        "UPDATE receipts SET remaining_cents = remaining_cents - ? WHERE receipt_id = ?",
        (data.amount_cents, receipt["receipt_id"]),
    )
    receivable = _get_receivable_or_404(conn, receipt["receivable_id"])
    restored_remaining = receivable["remaining_cents"] + data.amount_cents
    conn.execute(
        "UPDATE receivables SET remaining_cents = ?, status = 'open' WHERE receivable_id = ?",
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


def guarantee_fund_view(conn: sqlite3.Connection, fund_id: str) -> dict[str, Any]:
    row = _get_fund_or_404(conn, fund_id)
    return {
        "id": row["fund_id"],
        "fund_id": row["fund_id"],
        "fund_no": row["fund_no"],
        "name": row["name"],
        "available_cents": row["available_cents"],
        "available_balance_cents": row["available_cents"],
        "gap_cents": row["gap_cents"],
        "gap_amount_cents": row["gap_cents"],
        "shortfall_cents": row["gap_cents"],
        # available_cents is usable cash.  net_position includes gap as a
        # negative/unfunded deficit; expose both interpretations explicitly.
        "balance_cents": row["available_cents"],
        "net_balance_cents": row["available_cents"] - row["gap_cents"],
        "net_position_cents": row["available_cents"] - row["gap_cents"],
        "cash_balance_cents": row["available_cents"],
        "total_contribution_cents": row["total_contribution_cents"],
        "total_compensation_cents": row["total_compensation_cents"],
        "total_recovery_cents": row["total_recovery_cents"],
        "total_refund_clawback_cents": row["total_refund_clawback_cents"],
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def guarantee_fund_detail(conn: sqlite3.Connection, fund_id: str) -> dict[str, Any]:
    result = guarantee_fund_view(conn, fund_id)
    contributions = list(
        conn.execute(
            "SELECT * FROM fund_contributions WHERE fund_id = ? ORDER BY rowid ASC",
            (fund_id,),
        ).fetchall()
    )
    ledger = list(
        conn.execute(
            "SELECT * FROM fund_ledger WHERE fund_id = ? ORDER BY rowid ASC",
            (fund_id,),
        ).fetchall()
    )
    bindings = list(
        conn.execute(
            "SELECT binding_id FROM receivable_fund_bindings WHERE fund_id = ? ORDER BY rowid ASC",
            (fund_id,),
        ).fetchall()
    )
    result["contributions"] = [
        {
            "contribution_id": item["contribution_id"],
            "amount_cents": item["amount_cents"],
            "note": item["note"],
            "operator_account_id": item["operator_account_id"],
            "created_at": item["created_at"],
        }
        for item in contributions
    ]
    result["binding_ids"] = [item["binding_id"] for item in bindings]
    result["ledger"] = [
        {
            "ledger_id": item["ledger_id"],
            "event_type": item["event_type"],
            "ref_type": item["ref_type"],
            "ref_id": item["ref_id"],
            "gross_cents": item["gross_cents"],
            "delta_available": item["delta_available"],
            "delta_gap": item["delta_gap"],
            "available_after": item["available_after"],
            "gap_after": item["gap_after"],
            "created_at": item["created_at"],
        }
        for item in ledger
    ]
    return result


def list_guarantee_funds(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT fund_id FROM guarantee_funds ORDER BY created_at DESC, rowid DESC"
    ).fetchall()
    return {"funds": [guarantee_fund_view(conn, row["fund_id"]) for row in rows]}


def guarantee_binding_view(conn: sqlite3.Connection, binding_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM receivable_fund_bindings WHERE binding_id = ?", (binding_id,)
    ).fetchone()
    if row is None:
        raise ApiError(
            404, "GUARANTEE_BINDING_NOT_FOUND", f"Guarantee binding {binding_id!r} was not found."
        )
    outstanding = _outstanding_compensation_cents(conn, row["receivable_id"])
    limit_cents = row["compensation_limit_cents"]
    signed_headroom = limit_cents - outstanding
    return {
        "id": row["binding_id"],
        "binding_id": row["binding_id"],
        "receivable_id": row["receivable_id"],
        "fund_id": row["fund_id"],
        "compensation_limit_cents": limit_cents,
        "limit_cents": limit_cents,
        "limit_amount_cents": limit_cents,
        "outstanding_compensation_cents": outstanding,
        "compensation_outstanding_cents": outstanding,
        "remaining_limit_cents": max(0, signed_headroom),
        "remaining_compensation_limit_cents": max(0, signed_headroom),
        "available_limit_cents": max(0, signed_headroom),
        "headroom_cents": signed_headroom,
        "limit_headroom_cents": signed_headroom,
        "over_limit_cents": max(0, -signed_headroom),
        "limit_excess_cents": max(0, -signed_headroom),
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "fund": guarantee_fund_view(conn, row["fund_id"]),
    }


def compensation_view(conn: sqlite3.Connection, compensation_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM guarantee_compensations WHERE compensation_id = ?",
        (compensation_id,),
    ).fetchone()
    if row is None:
        raise ApiError(
            404,
            "COMPENSATION_NOT_FOUND",
            f"Guarantee compensation {compensation_id!r} was not found.",
        )
    allocations = conn.execute(
        """
        SELECT allocation_id
        FROM receipt_guarantee_allocations
        WHERE compensation_id = ?
        ORDER BY position ASC, rowid ASC
        """,
        (compensation_id,),
    ).fetchall()
    amount = row["amount_cents"]
    recovered = row["recovered_cents"]
    return {
        "id": row["compensation_id"],
        "compensation_id": row["compensation_id"],
        "batch_id": row["compensation_id"],
        "receivable_id": row["receivable_id"],
        "fund_id": row["fund_id"],
        "creditor_account_id": row["creditor_account_id"],
        "seq": row["seq"],
        "amount_cents": amount,
        "compensated_principal_cents": amount,
        "recovered_cents": recovered,
        "recovered_principal_cents": recovered,
        "outstanding_cents": amount - recovered,
        "outstanding_principal_cents": amount - recovered,
        "unrecovered_cents": amount - recovered,
        "unrecovered_principal_cents": amount - recovered,
        "remaining_cents": amount - recovered,
        "remaining_principal_cents": amount - recovered,
        "balance_cents": amount - recovered,
        "batch_balance_cents": amount - recovered,
        "deduction_offset_cents": row["deduction_offset_cents"],
        "net_credited_cents": row["net_credited_cents"],
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "recovery_allocation_ids": [item["allocation_id"] for item in allocations],
    }


def list_compensations(
    conn: sqlite3.Connection,
    *,
    receivable_id: Optional[str] = None,
    fund_id: Optional[str] = None,
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if receivable_id is not None:
        _get_receivable_or_404(conn, receivable_id)
        clauses.append("receivable_id = ?")
        params.append(receivable_id)
    if fund_id is not None:
        _get_fund_or_404(conn, fund_id)
        clauses.append("fund_id = ?")
        params.append(fund_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
        SELECT compensation_id FROM guarantee_compensations
        {where}
        ORDER BY seq ASC, rowid ASC
        """,  # noqa: S608 - fixed clauses and parameterized values
        params,
    ).fetchall()
    return {"compensations": [compensation_view(conn, row["compensation_id"]) for row in rows]}


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
    holdings = _holdings_view(conn, receivable_id)
    result["holdings"] = holdings
    result["ordinary_holdings"] = holdings
    ordinary_total = sum(item["held_cents"] for item in holdings)
    result["ordinary_remaining_cents"] = ordinary_total
    result["ordinary_unrecovered_cents"] = ordinary_total
    result["ordinary_unrecovered_principal_cents"] = ordinary_total
    result["ordinary_outstanding_cents"] = ordinary_total
    result["ordinary_principal_remaining_cents"] = ordinary_total
    result["ordinary_principal_cents"] = ordinary_total

    binding_row = _binding_by_receivable(conn, receivable_id)
    if binding_row is None:
        result["guarantee_binding"] = None
        result["fund_binding"] = None
        result["fund_id"] = None
        result["compensation_limit_cents"] = None
        result["compensation_batches"] = []
        result["guarantee_batches"] = []
        result["batches"] = []
        result["guarantee_outstanding_cents"] = 0
        result["subrogation_outstanding_cents"] = 0
    else:
        binding = guarantee_binding_view(conn, binding_row["binding_id"])
        batches = list(
            conn.execute(
                "SELECT compensation_id FROM guarantee_compensations WHERE receivable_id = ? ORDER BY seq ASC, rowid ASC",
                (receivable_id,),
            ).fetchall()
        )
        batch_views = [
            compensation_view(conn, item["compensation_id"]) for item in batches
        ]
        outstanding = sum(item["outstanding_cents"] for item in batch_views)
        result["guarantee_binding"] = binding
        result["fund_binding"] = binding
        result["fund_id"] = binding_row["fund_id"]
        result["compensation_limit_cents"] = binding_row["compensation_limit_cents"]
        result["compensation_batches"] = batch_views
        result["guarantee_batches"] = batch_views
        result["batches"] = batch_views
        result["guarantee_outstanding_cents"] = outstanding
        result["subrogation_outstanding_cents"] = outstanding
        result["subrogation_balance_cents"] = outstanding

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
    guarantee_allocations = list(
        conn.execute(
            """
            SELECT ga.*, gc.seq AS compensation_seq, gc.creditor_account_id
            FROM receipt_guarantee_allocations ga
            JOIN guarantee_compensations gc ON gc.compensation_id = ga.compensation_id
            WHERE ga.receipt_id = ?
            ORDER BY ga.position ASC, ga.rowid ASC
            """,
            (receipt_id,),
        ).fetchall()
    )
    guarantee_allocation_views = [
        {
            "kind": "guarantee",
            "allocation_id": item["allocation_id"],
            "guarantee_allocation_id": item["allocation_id"],
            "compensation_id": item["compensation_id"],
            "batch_id": item["compensation_id"],
            "compensation_seq": item["compensation_seq"],
            "fund_id": item["fund_id"],
            "creditor_account_id": item["creditor_account_id"],
            "position": item["position"],
            "amount_cents": item["amount_cents"],
            "reversed_cents": item["reversed_cents"],
            "unreversed_cents": item["amount_cents"] - item["reversed_cents"],
            "gap_offset_cents": item["gap_offset_cents"],
            "available_credited_cents": item["available_credited_cents"],
        }
        for item in guarantee_allocations
    ]
    refunds = list(
        conn.execute(
            "SELECT * FROM refunds WHERE receipt_id = ? ORDER BY rowid ASC", (receipt_id,)
        ).fetchall()
    )
    refunded_total = sum(item["amount_cents"] for item in refunds)
    ordinary_allocation_views = [
        {
            "kind": "ordinary",
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
    ]
    all_allocation_views = [
        dict(item, kind="guarantee") for item in guarantee_allocation_views
    ] + ordinary_allocation_views
    return {
        "receipt_id": row["receipt_id"],
        "receivable_id": row["receivable_id"],
        "channel_serial_no": row["channel_serial_no"],
        "amount_cents": row["amount_cents"],
        "remaining_cents": row["remaining_cents"],
        "refunded_cents": refunded_total,
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        # Backward-compatible meaning: allocations are ordinary creditor lines.
        "allocations": ordinary_allocation_views,
        "ordinary_allocations": ordinary_allocation_views,
        "all_allocations": all_allocation_views,
        "distributions": all_allocation_views,
        "guarantee_allocations": guarantee_allocation_views,
        "fund_allocations": guarantee_allocation_views,
        "compensation_allocations": guarantee_allocation_views,
        "batch_allocations": guarantee_allocation_views,
        "subrogation_allocations": guarantee_allocation_views,
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
    guarantee_reversals = list(
        conn.execute(
            """
            SELECT * FROM refund_guarantee_reversals
            WHERE refund_id = ?
            ORDER BY position ASC, rowid ASC
            """,
            (refund_id,),
        ).fetchall()
    )
    ordinary_views = [
        {
            "kind": "ordinary",
            "reversal_id": item["reversal_id"],
            "allocation_id": item["allocation_id"],
            "account_id": item["account_id"],
            "position": item["position"],
            "amount_cents": item["amount_cents"],
            "clawback_from_balance_cents": item["clawback_from_balance"],
            "clawback_to_deduction_cents": item["clawback_to_deduction"],
        }
        for item in reversals
    ]
    guarantee_views = [
        {
            "kind": "guarantee",
            "reversal_id": item["reversal_id"],
            "guarantee_reversal_id": item["reversal_id"],
            "guarantee_allocation_id": item["guarantee_allocation_id"],
            "allocation_id": item["guarantee_allocation_id"],
            "compensation_id": item["compensation_id"],
            "batch_id": item["compensation_id"],
            "fund_id": item["fund_id"],
            "position": item["position"],
            "amount_cents": item["amount_cents"],
            "deducted_available_cents": item["deducted_available_cents"],
            "fund_deducted_cents": item["deducted_available_cents"],
            "gap_added_cents": item["gap_added_cents"],
            "gap_cents": item["gap_added_cents"],
        }
        for item in guarantee_reversals
    ]
    all_reversals = sorted(
        ordinary_views + guarantee_views,
        key=lambda item: (item["position"], item["kind"], item["reversal_id"]),
    )
    return {
        "refund_id": row["refund_id"],
        "receipt_id": row["receipt_id"],
        "channel_serial_no": row["channel_serial_no"],
        "amount_cents": row["amount_cents"],
        "operator_account_id": row["operator_account_id"],
        "created_at": row["created_at"],
        "reversals": ordinary_views,
        "ordinary_reversals": ordinary_views,
        "guarantee_reversals": guarantee_views,
        "fund_reversals": guarantee_views,
        "compensation_reversals": guarantee_views,
        "batch_reversals": guarantee_views,
        "subrogation_reversals": guarantee_views,
        "all_reversals": all_reversals,
        "distribution_reversals": all_reversals,
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


# Domain-name aliases used by some callers and route conventions.
create_fund_tx = create_guarantee_fund_tx
register_fund_top_up_tx = register_fund_contribution_tx
register_fund_topup_tx = register_fund_contribution_tx
bind_fund_tx = bind_receivable_fund_tx
create_compensation_tx = register_compensation_tx
register_advance_tx = register_compensation_tx

# Additional non-_tx naming aliases for direct service callers.
create_guarantee_fund = create_guarantee_fund_tx
register_fund_contribution = register_fund_contribution_tx
bind_receivable_fund = bind_receivable_fund_tx
register_compensation = register_compensation_tx
