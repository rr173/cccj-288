"""Core signing, delegation, stage, cancellation, and certificate logic."""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature

from .errors import ApiError
from .security import (
    b64d,
    b64e,
    canonical_json_bytes,
    canonical_json_text,
    new_id,
    public_key_from_b64,
    sha256_hex,
    sha256_id,
    utc_now,
    verify_ed25519_b64,
)

CHALLENGE_SCHEMA = "multi-party-agreement-signing-challenge/v1"
CERTIFICATE_SCHEMA = "multi-party-agreement-signed-certificate/v1"


# ---------------------------------------------------------------------------
# Row/view helpers
# ---------------------------------------------------------------------------


def _account_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "account_id": row["account_id"],
        "public_key_b64": row["public_key_b64"],
        "display_name": row["display_name"],
        "created_at": row["created_at"],
    }


def get_account(conn: sqlite3.Connection, account_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()


def account_or_404(conn: sqlite3.Connection, account_id: str) -> sqlite3.Row:
    row = get_account(conn, account_id)
    if row is None:
        raise ApiError(404, "ACCOUNT_NOT_FOUND", f"Account {account_id!r} is not registered.")
    return row


def _seat_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "seat_id": row["seat_id"],
        "seat_key": row["seat_key"],
        "label": row["label"],
        "stage": row["stage"],
        "position": row["position"],
        "original_account_id": row["original_account_id"],
        "status": row["status"],
        "current_account_id": row["current_account_id"],
        "current_delegation_id": row["current_delegation_id"],
        "authority_generation": row["authority_generation"],
        "signature_id": row["signature_id"],
        "signed_by_account_id": row["signed_by_account_id"],
        "signed_at": row["signed_at"],
    }


def get_agreement_or_404(conn: sqlite3.Connection, agreement_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM agreements WHERE agreement_id = ?", (agreement_id,)).fetchone()
    if row is None:
        raise ApiError(404, "AGREEMENT_NOT_FOUND", f"Agreement {agreement_id!r} was not found.")
    return row


def get_seat_or_404(conn: sqlite3.Connection, agreement_id: str, seat_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM seats WHERE agreement_id = ? AND seat_id = ?",
        (agreement_id, seat_id),
    ).fetchone()
    if row is None:
        raise ApiError(404, "SEAT_NOT_FOUND", f"Seat {seat_id!r} was not found in this agreement.")
    return row


def list_seats(conn: sqlite3.Connection, agreement_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM seats WHERE agreement_id = ? ORDER BY stage ASC, position ASC",
            (agreement_id,),
        ).fetchall()
    )


def agreement_detail(conn: sqlite3.Connection, agreement_id: str) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    seats = list_seats(conn, agreement_id)
    signed = sum(1 for seat in seats if seat["status"] == "signed")
    return {
        "agreement_id": agreement["agreement_id"],
        "initiator_account_id": agreement["initiator_account_id"],
        "title": agreement["title"],
        "status": agreement["status"],
        "content_sha256": f"sha256:{agreement['content_sha256']}",
        "content_byte_length": len(agreement["content"]),
        "created_at": agreement["created_at"],
        "sent_at": agreement["sent_at"],
        "completed_at": agreement["completed_at"],
        "cancelled_at": agreement["cancelled_at"],
        "cancel_reason": agreement["cancel_reason"],
        "seat_count": len(seats),
        "signed_count": signed,
        "seats": [_seat_dict(seat) for seat in seats],
    }


# ---------------------------------------------------------------------------
# Accounts and agreement preparation
# ---------------------------------------------------------------------------


def create_account_tx(conn: sqlite3.Connection, data: Any) -> tuple[int, dict[str, Any]]:
    try:
        public_key_from_b64(data.public_key_b64)
    except (ValueError, Exception) as exc:  # cryptography raises broad internal errors
        raise ApiError(400, "INVALID_PUBLIC_KEY", "public_key_b64 is not a valid raw Ed25519 key.") from exc

    existing = get_account(conn, data.account_id)
    if existing is not None:
        if existing["public_key_b64"] != data.public_key_b64:
            raise ApiError(
                409,
                "ACCOUNT_KEY_CONFLICT",
                "Account already exists with a different public key.",
            )
        return 200, _account_dict(existing)

    # Also guard against the same public key being registered under another ID.
    same_key = conn.execute(
        "SELECT * FROM accounts WHERE public_key_b64 = ?", (data.public_key_b64,)
    ).fetchone()
    if same_key is not None:
        raise ApiError(
            409,
            "PUBLIC_KEY_ALREADY_REGISTERED",
            "This public key is already registered to another account.",
            {"existing_account_id": same_key["account_id"]},
        )

    now = utc_now()
    conn.execute(
        """
        INSERT INTO accounts (account_id, public_key_b64, display_name, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (data.account_id, data.public_key_b64, data.display_name, now),
    )
    row = get_account(conn, data.account_id)
    assert row is not None
    return 201, _account_dict(row)


def _decode_agreement_content(data: Any) -> bytes:
    if data.content_text is not None:
        return data.content_text.encode("utf-8")
    try:
        return b64d(data.content_base64 or "")
    except Exception as exc:
        raise ApiError(400, "INVALID_CONTENT_BASE64", "content_base64 is not valid base64.") from exc


def create_agreement_tx(conn: sqlite3.Connection, data: Any) -> dict[str, Any]:
    content = _decode_agreement_content(data)
    if not content:
        raise ApiError(400, "EMPTY_CONTENT", "Agreement body must not be empty.")

    seen_keys: set[str] = set()
    for index, seat in enumerate(data.seats, start=1):
        key = seat.seat_key or f"seat_{index}"
        if key in seen_keys:
            raise ApiError(400, "DUPLICATE_SEAT_KEY", f"Seat key {key!r} is duplicated.")
        seen_keys.add(key)
        account_or_404(conn, seat.original_account_id)

    agreement_id = new_id("agr")
    now = utc_now()
    conn.execute(
        """
        INSERT INTO agreements (
            agreement_id, initiator_account_id, title, content, content_sha256,
            status, created_at
        ) VALUES (?, ?, ?, ?, ?, 'draft', ?)
        """,
        (agreement_id, data.initiator_account_id, data.title, content, sha256_hex(content), now),
    )

    for index, seat in enumerate(data.seats, start=1):
        seat_id = new_id("seat")
        key = seat.seat_key or f"seat_{index}"
        conn.execute(
            """
            INSERT INTO seats (
                seat_id, agreement_id, seat_key, label, stage, position,
                original_account_id, status, current_account_id, authority_generation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, 0)
            """,
            (
                seat_id,
                agreement_id,
                key,
                seat.label,
                seat.stage,
                index,
                seat.original_account_id,
                seat.original_account_id,
            ),
        )

    return agreement_detail(conn, agreement_id)


def send_agreement_tx(conn: sqlite3.Connection, agreement_id: str, data: Any) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    if agreement["initiator_account_id"] != data.initiator_account_id:
        raise ApiError(403, "NOT_INITIATOR", "Only the agreement initiator may send it.")
    if agreement["status"] != "draft":
        raise ApiError(
            409,
            "AGREEMENT_NOT_DRAFT",
            f"Agreement cannot be sent from status {agreement['status']!r}.",
            {"status": agreement["status"]},
        )

    conn.execute(
        "UPDATE agreements SET status = 'active', sent_at = ? WHERE agreement_id = ?",
        (utc_now(), agreement_id),
    )
    return agreement_detail(conn, agreement_id)


def cancel_agreement_tx(conn: sqlite3.Connection, agreement_id: str, data: Any) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    if agreement["initiator_account_id"] != data.initiator_account_id:
        raise ApiError(403, "NOT_INITIATOR", "Only the agreement initiator may cancel it.")
    if agreement["status"] == "cancelled":
        raise ApiError(409, "AGREEMENT_ALREADY_CANCELLED", "Agreement is already cancelled.")
    if agreement["status"] == "completed":
        raise ApiError(409, "AGREEMENT_COMPLETED", "A fully signed agreement cannot be cancelled.")

    now = utc_now()
    conn.execute(
        """
        UPDATE agreements
        SET status = 'cancelled', cancelled_at = ?, cancel_reason = ?
        WHERE agreement_id = ?
        """,
        (now, data.reason, agreement_id),
    )
    # Pending seats are cancelled. Signed rows and signatures remain untouched.
    conn.execute(
        "UPDATE seats SET status = 'cancelled' WHERE agreement_id = ? AND status = 'pending'",
        (agreement_id,),
    )
    detail = agreement_detail(conn, agreement_id)

    # If this agreement is the dedicated agreement of a pending set-off round,
    # cancel/release that round in the same transaction.  Lazy import avoids a
    # module import cycle (setoff imports settlement/service helpers).
    from .setoff import handle_agreement_cancelled_tx

    linked_round = handle_agreement_cancelled_tx(conn, agreement_id)
    if linked_round is not None:
        detail["setoff_round"] = linked_round
    return detail


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------


def _active_delegations(conn: sqlite3.Connection, seat_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT * FROM delegations
            WHERE seat_id = ? AND revocation_id IS NULL
            ORDER BY seq ASC, rowid ASC
            """,
            (seat_id,),
        ).fetchall()
    )


def _authority_snapshot(
    conn: sqlite3.Connection, agreement: sqlite3.Row, seat: sqlite3.Row
) -> dict[str, Any]:
    active = _active_delegations(conn, seat["seat_id"])
    all_delegations = list(
        conn.execute(
            "SELECT * FROM delegations WHERE seat_id = ? ORDER BY rowid ASC",
            (seat["seat_id"],),
        ).fetchall()
    )
    revocations = list(
        conn.execute(
            "SELECT * FROM revocations WHERE seat_id = ? ORDER BY rowid ASC",
            (seat["seat_id"],),
        ).fetchall()
    )

    return {
        "original_account_id": seat["original_account_id"],
        "current_account_id": seat["current_account_id"],
        "authority_generation": seat["authority_generation"],
        "authority_basis": "ORIGINAL" if not active else "DELEGATION",
        "active_chain": [
            {
                "delegation_id": row["delegation_id"],
                "seq": row["seq"],
                "parent_delegation_id": row["parent_delegation_id"],
                "delegator_account_id": row["delegator_account_id"],
                "delegatee_account_id": row["delegatee_account_id"],
                "created_at": row["created_at"],
            }
            for row in active
        ],
        "delegation_history": [
            {
                "delegation_id": row["delegation_id"],
                "seq": row["seq"],
                "parent_delegation_id": row["parent_delegation_id"],
                "delegator_account_id": row["delegator_account_id"],
                "delegatee_account_id": row["delegatee_account_id"],
                "operation_id": row["operation_id"],
                "revocation_id": row["revocation_id"],
                "created_at": row["created_at"],
                "revoked_at": row["revoked_at"],
            }
            for row in all_delegations
        ],
        "revocation_history": [
            {
                "revocation_id": row["revocation_id"],
                "initiator_account_id": row["initiator_account_id"],
                "operation_id": row["operation_id"],
                "revoked_head_delegation_id": row["revoked_head_delegation_id"],
                "revoked_chain": json.loads(row["revoked_chain_json"]),
                "created_at": row["created_at"],
            }
            for row in revocations
        ],
    }


def delegation_snapshot(
    conn: sqlite3.Connection, agreement_id: str, seat_id: str
) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    seat = get_seat_or_404(conn, agreement_id, seat_id)
    return _authority_snapshot(conn, agreement, seat)


def delegate_seat_tx(
    conn: sqlite3.Connection, agreement_id: str, seat_id: str, data: Any
) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    seat = get_seat_or_404(conn, agreement_id, seat_id)

    if agreement["status"] != "active":
        raise ApiError(
            409,
            "AGREEMENT_NOT_ACTIVE",
            "Delegation is allowed only after the agreement has been sent and before it ends.",
            {"status": agreement["status"]},
        )
    if seat["status"] != "pending":
        raise ApiError(
            409,
            "SEAT_NOT_PENDING",
            "Only an unfinished seat can be delegated.",
            {"status": seat["status"]},
        )
    if data.actor_account_id != seat["current_account_id"]:
        raise ApiError(
            403,
            "NOT_CURRENT_AUTHORITY",
            "Only the current authorized account for this unfinished seat may delegate it.",
            {
                "current_authorized_account_id": seat["current_account_id"],
                "actor_account_id": data.actor_account_id,
            },
        )
    if data.delegatee_account_id == data.actor_account_id:
        raise ApiError(400, "SELF_DELEGATION", "An account cannot delegate a seat to itself.")

    account_or_404(conn, data.delegatee_account_id)

    active = _active_delegations(conn, seat_id)
    path = [seat["original_account_id"]]
    for row in active:
        path.append(row["delegatee_account_id"])

    if data.delegatee_account_id in path:
        raise ApiError(
            409,
            "DELEGATION_CYCLE",
            "Delegation would create a ring because the recipient is already in the active chain.",
            {"active_authority_path": path, "delegatee_account_id": data.delegatee_account_id},
        )

    delegation_id = new_id("del")
    now = utc_now()
    seq = len(active) + 1
    parent_id = seat["current_delegation_id"]
    conn.execute(
        """
        INSERT INTO delegations (
            delegation_id, agreement_id, seat_id, seq, parent_delegation_id,
            delegator_account_id, delegatee_account_id, operation_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            delegation_id,
            agreement_id,
            seat_id,
            seq,
            parent_id,
            data.actor_account_id,
            data.delegatee_account_id,
            data.operation_id,
            now,
        ),
    )
    conn.execute(
        """
        UPDATE seats
        SET current_account_id = ?, current_delegation_id = ?,
            authority_generation = authority_generation + 1
        WHERE seat_id = ?
        """,
        (data.delegatee_account_id, delegation_id, seat_id),
    )

    return {
        "delegation_id": delegation_id,
        "agreement_id": agreement_id,
        "seat_id": seat_id,
        "seq": seq,
        "parent_delegation_id": parent_id,
        "delegator_account_id": data.actor_account_id,
        "delegatee_account_id": data.delegatee_account_id,
        "created_at": now,
        "seat": _seat_dict(get_seat_or_404(conn, agreement_id, seat_id)),
    }


def revoke_delegation_tx(
    conn: sqlite3.Connection, agreement_id: str, seat_id: str, data: Any
) -> dict[str, Any]:
    agreement = get_agreement_or_404(conn, agreement_id)
    seat = get_seat_or_404(conn, agreement_id, seat_id)

    if agreement["initiator_account_id"] != data.initiator_account_id:
        raise ApiError(403, "NOT_INITIATOR", "Only the agreement initiator may revoke delegation chains.")
    if agreement["status"] != "active":
        raise ApiError(409, "AGREEMENT_NOT_ACTIVE", "This agreement is not active.", {"status": agreement["status"]})
    if seat["status"] != "pending":
        raise ApiError(
            409,
            "SEAT_NOT_PENDING",
            "A completed signature cannot be renamed or have its delegation retroactively revoked.",
            {"status": seat["status"]},
        )
    active = _active_delegations(conn, seat_id)
    if not active:
        raise ApiError(409, "NO_ACTIVE_DELEGATION", "This seat currently has no delegation chain to revoke.")

    revocation_id = new_id("rev")
    now = utc_now()
    chain_snapshot = [
        {
            "delegation_id": row["delegation_id"],
            "seq": row["seq"],
            "delegator_account_id": row["delegator_account_id"],
            "delegatee_account_id": row["delegatee_account_id"],
            "created_at": row["created_at"],
        }
        for row in active
    ]
    head_id = seat["current_delegation_id"]

    conn.execute(
        """
        INSERT INTO revocations (
            revocation_id, agreement_id, seat_id, initiator_account_id,
            operation_id, revoked_head_delegation_id, revoked_chain_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            revocation_id,
            agreement_id,
            seat_id,
            data.initiator_account_id,
            data.operation_id,
            head_id,
            canonical_json_text(chain_snapshot),
            now,
        ),
    )
    conn.execute(
        """
        UPDATE delegations
        SET revocation_id = ?, revoked_at = ?
        WHERE seat_id = ? AND revocation_id IS NULL
        """,
        (revocation_id, now, seat_id),
    )
    conn.execute(
        """
        UPDATE seats
        SET current_account_id = original_account_id,
            current_delegation_id = NULL,
            authority_generation = authority_generation + 1
        WHERE seat_id = ?
        """,
        (seat_id,),
    )

    return {
        "revocation_id": revocation_id,
        "agreement_id": agreement_id,
        "seat_id": seat_id,
        "revoked_head_delegation_id": head_id,
        "revoked_chain": chain_snapshot,
        "restored_account_id": seat["original_account_id"],
        "created_at": now,
        "seat": _seat_dict(get_seat_or_404(conn, agreement_id, seat_id)),
    }


# ---------------------------------------------------------------------------
# Stage gate and challenges
# ---------------------------------------------------------------------------


def _stage_gate_snapshot(conn: sqlite3.Connection, agreement_id: str, stage: int) -> dict[str, Any]:
    lower_total = conn.execute(
        "SELECT COUNT(*) AS n FROM seats WHERE agreement_id = ? AND stage < ?",
        (agreement_id, stage),
    ).fetchone()["n"]
    lower_signed = conn.execute(
        """
        SELECT s.seat_id AS seat_id, s.stage AS stage, sig.signature_id AS signature_id
        FROM seats s
        JOIN signatures sig ON sig.seat_id = s.seat_id
        WHERE s.agreement_id = ? AND s.stage < ?
        ORDER BY s.stage ASC, s.position ASC
        """,
        (agreement_id, stage),
    ).fetchall()

    if len(lower_signed) != lower_total:
        unsigned = conn.execute(
            """
            SELECT seat_id, seat_key, stage FROM seats
            WHERE agreement_id = ? AND stage < ? AND status != 'signed'
            ORDER BY stage, position
            """,
            (agreement_id, stage),
        ).fetchall()
        raise ApiError(
            409,
            "STAGE_LOCKED",
            "All seats in earlier stages must be signed before this stage can issue a challenge.",
            {"stage": stage, "unsigned_lower_stage_seats": [dict(row) for row in unsigned]},
        )

    return {
        "current_stage": stage,
        "all_lower_stages_completed": True,
        "lower_stage_seat_count": lower_total,
        "completed_lower_seats": [
            {
                "seat_id": row["seat_id"],
                "stage": row["stage"],
                "signature_id": row["signature_id"],
            }
            for row in lower_signed
        ],
        "completed_lower_stage_signature_ids": [row["signature_id"] for row in lower_signed],
    }


def issue_challenge_tx(
    conn: sqlite3.Connection,
    agreement_id: str,
    seat_id: str,
    data: Any,
) -> tuple[bytes, dict[str, str]]:
    agreement = get_agreement_or_404(conn, agreement_id)
    seat = get_seat_or_404(conn, agreement_id, seat_id)
    account = account_or_404(conn, data.account_id)

    if agreement["status"] != "active":
        raise ApiError(
            409,
            "AGREEMENT_NOT_ACTIVE",
            "Challenges can only be issued for a sent, active agreement.",
            {"status": agreement["status"]},
        )
    if seat["status"] != "pending":
        raise ApiError(409, "SEAT_NOT_PENDING", "This seat is already completed or cancelled.")
    if data.account_id != seat["current_account_id"]:
        raise ApiError(
            403,
            "NOT_CURRENT_AUTHORITY",
            "The challenge account is not currently authorized for this seat.",
            {"current_authorized_account_id": seat["current_account_id"]},
        )

    # Raises STAGE_LOCKED if an earlier stage is incomplete.
    stage_gate = _stage_gate_snapshot(conn, agreement_id, seat["stage"])
    authority = _authority_snapshot(conn, agreement, seat)
    authority_hash = sha256_id(canonical_json_bytes(authority))

    challenge_id = new_id("chal")
    issued_at = utc_now()
    challenge = {
        "schema": CHALLENGE_SCHEMA,
        "challenge_id": challenge_id,
        "agreement_id": agreement_id,
        "title": agreement["title"],
        "body_sha256": sha256_id(agreement["content"]),
        "seat": {
            "seat_id": seat_id,
            "seat_key": seat["seat_key"],
            "label": seat["label"],
            "stage": seat["stage"],
            "original_account_id": seat["original_account_id"],
        },
        "signer": {
            "account_id": account["account_id"],
            "public_key_b64": account["public_key_b64"],
        },
        "authority": authority,
        "authority_hash": authority_hash,
        "stage_gate": stage_gate,
        "nonce_b64": b64e(os.urandom(32)),
        "issued_at": issued_at,
    }
    challenge_bytes = canonical_json_bytes(challenge)

    conn.execute(
        """
        INSERT INTO challenges (
            challenge_id, agreement_id, seat_id, operation_id, account_id,
            signer_public_key_b64, challenge_bytes, challenge_sha256, body_sha256,
            stage, authority_generation, authority_hash, status, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?)
        """,
        (
            challenge_id,
            agreement_id,
            seat_id,
            data.operation_id,
            data.account_id,
            account["public_key_b64"],
            challenge_bytes,
            sha256_id(challenge_bytes),
            sha256_id(agreement["content"]),
            seat["stage"],
            seat["authority_generation"],
            authority_hash,
            issued_at,
        ),
    )

    headers = {
        "X-Challenge-Id": challenge_id,
        "X-Challenge-Sha256": sha256_id(challenge_bytes),
    }
    return challenge_bytes, headers


# ---------------------------------------------------------------------------
# Signature submission and completion
# ---------------------------------------------------------------------------


def _certificate_core(conn: sqlite3.Connection, agreement: sqlite3.Row, certificate_id: str) -> dict[str, Any]:
    seats = list_seats(conn, agreement["agreement_id"])
    seat_views: list[dict[str, Any]] = []

    for seat in seats:
        if seat["status"] != "signed" or not seat["signature_id"]:
            raise ApiError(409, "CERTIFICATE_NOT_READY", "Not every seat is signed.")
        signature = conn.execute(
            "SELECT * FROM signatures WHERE signature_id = ?", (seat["signature_id"],)
        ).fetchone()
        if signature is None:
            raise ApiError(500, "SIGNATURE_RECORD_MISSING", "Signed seat has no signature row.")
        challenge = conn.execute(
            "SELECT * FROM challenges WHERE challenge_id = ?", (signature["challenge_id"],)
        ).fetchone()
        if challenge is None:
            raise ApiError(500, "CHALLENGE_RECORD_MISSING", "Signature has no challenge row.")

        challenge_obj = json.loads(bytes(challenge["challenge_bytes"]).decode("utf-8"))
        delegation_source = json.loads(signature["delegation_source_json"])
        stage_gate = json.loads(signature["stage_gate_json"])

        seat_views.append(
            {
                "seat_id": seat["seat_id"],
                "seat_key": seat["seat_key"],
                "label": seat["label"],
                "stage": seat["stage"],
                "position": seat["position"],
                "original_account_id": seat["original_account_id"],
                "status": "signed",
                "completed_at": seat["signed_at"],
                "actual_signer_account_id": signature["actual_signer_account_id"],
                "signature": {
                    "signature_id": signature["signature_id"],
                    "challenge_id": signature["challenge_id"],
                    "operation_id": signature["operation_id"],
                    "signed_at": signature["signed_at"],
                    "original_account_id": signature["original_account_id"],
                    "actual_signer_account_id": signature["actual_signer_account_id"],
                    "signature_b64": signature["signature_b64"],
                    "signer_public_key_b64": signature["signer_public_key_b64"],
                    "challenge_b64": b64e(bytes(challenge["challenge_bytes"])),
                    "challenge_sha256": challenge["challenge_sha256"],
                    "body_sha256": signature["body_sha256"],
                    "authority_generation": signature["authority_generation"],
                    "delegation_source": delegation_source,
                    "stage_gate": stage_gate,
                    "challenge": challenge_obj,
                },
            }
        )

    stage_rows = conn.execute(
        """
        SELECT stage,
               COUNT(*) AS seat_count,
               SUM(CASE WHEN status = 'signed' THEN 1 ELSE 0 END) AS signed_count
        FROM seats
        WHERE agreement_id = ?
        GROUP BY stage
        ORDER BY stage
        """,
        (agreement["agreement_id"],),
    ).fetchall()
    stage_summary = [
        {
            "stage": row["stage"],
            "seat_count": row["seat_count"],
            "signed_count": row["signed_count"],
            "complete": row["seat_count"] == row["signed_count"],
        }
        for row in stage_rows
    ]

    return {
        "schema": CERTIFICATE_SCHEMA,
        "certificate_id": certificate_id,
        "agreement_id": agreement["agreement_id"],
        "title": agreement["title"],
        "initiator_account_id": agreement["initiator_account_id"],
        "created_at": agreement["created_at"],
        "sent_at": agreement["sent_at"],
        "completed_at": agreement["completed_at"],
        "body": {
            "encoding": "base64",
            "data": b64e(bytes(agreement["content"])),
            "sha256": sha256_id(bytes(agreement["content"])),
            "byte_length": len(agreement["content"]),
        },
        "stage_summary": stage_summary,
        "seats": seat_views,
        "verification": {
            "signature_algorithm": "Ed25519",
            "signature_message": "exact canonical challenge_bytes returned by /challenges",
            "body_hash_algorithm": "SHA-256",
            "canonical_json": "UTF-8, sorted keys, compact separators",
        },
    }


def _complete_agreement_if_all_signed(
    conn: sqlite3.Connection, agreement_id: str
) -> Optional[dict[str, Any]]:
    counts = conn.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status = 'signed' THEN 1 ELSE 0 END) AS signed
        FROM seats WHERE agreement_id = ?
        """,
        (agreement_id,),
    ).fetchone()
    if counts["total"] != counts["signed"]:
        return None

    now = utc_now()
    conn.execute(
        "UPDATE agreements SET status = 'completed', completed_at = ? WHERE agreement_id = ?",
        (now, agreement_id),
    )
    agreement = get_agreement_or_404(conn, agreement_id)
    certificate_id = new_id("cert")
    certificate = _certificate_core(conn, agreement, certificate_id)
    certificate_hash = sha256_id(canonical_json_bytes(certificate))
    certificate["certificate_hash"] = certificate_hash
    certificate_text = json.dumps(certificate, ensure_ascii=False, indent=2, sort_keys=True)

    conn.execute(
        """
        INSERT INTO certificates (
            agreement_id, certificate_id, certificate_json,
            certificate_sha256, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (agreement_id, certificate_id, certificate_text, certificate_hash, now),
    )
    return certificate


def submit_signature_tx(
    conn: sqlite3.Connection, challenge_id: str, data: Any
) -> dict[str, Any]:
    challenge = conn.execute(
        "SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)
    ).fetchone()
    if challenge is None:
        raise ApiError(404, "CHALLENGE_NOT_FOUND", "Unknown challenge ID.")

    # Different operation IDs reusing a challenge must not create a second fact.
    existing_signature = conn.execute(
        "SELECT * FROM signatures WHERE challenge_id = ?", (challenge_id,)
    ).fetchone()
    if existing_signature is not None or challenge["status"] == "consumed":
        raise ApiError(
            409,
            "CHALLENGE_ALREADY_USED",
            "This one-time challenge has already produced a signature fact.",
            {
                "challenge_id": challenge_id,
                "signature_id": challenge["signature_id"]
                or (existing_signature["signature_id"] if existing_signature else None),
            },
        )

    agreement = get_agreement_or_404(conn, challenge["agreement_id"])
    seat = get_seat_or_404(conn, agreement["agreement_id"], challenge["seat_id"])
    seat_id = seat["seat_id"]
    account = account_or_404(conn, challenge["account_id"])

    # Current state checks are mandatory; cryptographic validity alone is not
    # permission to write a signature.
    if agreement["status"] != "active":
        raise ApiError(
            409,
            "AGREEMENT_NOT_ACTIVE",
            "Signature rejected because the agreement is not active.",
            {"status": agreement["status"]},
        )
    if seat["status"] != "pending":
        raise ApiError(409, "SEAT_NOT_PENDING", "This seat is no longer awaiting a signature.")

    current_generation = seat["authority_generation"]
    if current_generation != challenge["authority_generation"]:
        raise ApiError(
            409,
            "AUTHORITY_STALE",
            "Delegation or revocation changed after this challenge was issued. "
            "Request a new challenge from the current authorized account.",
            {
                "challenge_authority_generation": challenge["authority_generation"],
                "current_authority_generation": current_generation,
                "current_authorized_account_id": seat["current_account_id"],
            },
        )

    if challenge["account_id"] != seat["current_account_id"]:
        raise ApiError(
            403,
            "NOT_CURRENT_AUTHORITY",
            "Challenge account is no longer the current authorized account.",
            {
                "challenge_account_id": challenge["account_id"],
                "current_authorized_account_id": seat["current_account_id"],
            },
        )
    if account["public_key_b64"] != challenge["signer_public_key_b64"]:
        raise ApiError(409, "PUBLIC_KEY_CHANGED", "Registered public key no longer matches challenge.")

    # Recompute the complete qualification snapshot and compare it with issuance.
    authority = _authority_snapshot(conn, agreement, seat)
    authority_hash = sha256_id(canonical_json_bytes(authority))
    if authority_hash != challenge["authority_hash"]:
        raise ApiError(
            409,
            "AUTHORITY_SNAPSHOT_MISMATCH",
            "Current delegation source does not match the qualification bound into the challenge.",
        )

    # Stage gate remains satisfied; recompute for the permanent signature record.
    stage_gate = _stage_gate_snapshot(conn, agreement["agreement_id"], seat["stage"])

    try:
        verify_ed25519_b64(
            challenge["signer_public_key_b64"],
            bytes(challenge["challenge_bytes"]),
            data.signature_b64,
        )
    except InvalidSignature as exc:
        raise ApiError(
            422,
            "INVALID_SIGNATURE",
            "Ed25519 signature verification failed over the exact challenge bytes.",
        ) from exc
    except (ValueError, Exception) as exc:
        raise ApiError(400, "MALFORMED_SIGNATURE", "signature_b64 is not a valid 64-byte Ed25519 signature.") from exc

    signature_id = new_id("sig")
    signed_at = utc_now()
    delegation_source_json = canonical_json_text(authority)
    stage_gate_json = canonical_json_text(stage_gate)

    conn.execute(
        """
        INSERT INTO signatures (
            signature_id, agreement_id, seat_id, challenge_id, operation_id,
            stage, body_sha256, original_account_id, actual_signer_account_id,
            signer_public_key_b64, signature_b64, authority_generation,
            delegation_source_json, stage_gate_json, signed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature_id,
            agreement["agreement_id"],
            seat["seat_id"],
            challenge_id,
            data.operation_id,
            seat["stage"],
            challenge["body_sha256"],
            seat["original_account_id"],
            challenge["account_id"],
            challenge["signer_public_key_b64"],
            data.signature_b64,
            current_generation,
            delegation_source_json,
            stage_gate_json,
            signed_at,
        ),
    )
    conn.execute(
        """
        UPDATE seats
        SET status = 'signed', signature_id = ?, signed_by_account_id = ?, signed_at = ?
        WHERE seat_id = ? AND status = 'pending'
        """,
        (signature_id, challenge["account_id"], signed_at, seat_id),
    )
    if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
        # Defensive guard; the immediate transaction and status check normally
        # make this unreachable.
        raise ApiError(409, "SEAT_ALREADY_SIGNED", "Seat was completed by another transaction.")

    conn.execute(
        """
        UPDATE challenges
        SET status = 'consumed', signature_id = ?, consumed_at = ?
        WHERE challenge_id = ? AND status = 'issued'
        """,
        (signature_id, signed_at, challenge_id),
    )
    if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
        raise ApiError(409, "CHALLENGE_ALREADY_USED", "Challenge was consumed by another transaction.")

    certificate = _complete_agreement_if_all_signed(conn, agreement["agreement_id"])

    return {
        "signature_id": signature_id,
        "challenge_id": challenge_id,
        "agreement_id": agreement["agreement_id"],
        "seat_id": seat_id,
        "actual_signer_account_id": challenge["account_id"],
        "original_account_id": seat["original_account_id"],
        "authority_generation": current_generation,
        "signed_at": signed_at,
        "agreement_status": "completed" if certificate else "active",
        "certificate_available": certificate is not None,
        "certificate_url": (
            f"/agreements/{agreement['agreement_id']}/certificate" if certificate else None
        ),
    }


def get_certificate(conn: sqlite3.Connection, agreement_id: str) -> dict[str, Any]:
    get_agreement_or_404(conn, agreement_id)
    row = conn.execute(
        "SELECT certificate_json FROM certificates WHERE agreement_id = ?", (agreement_id,)
    ).fetchone()
    if row is None:
        raise ApiError(
            409,
            "CERTIFICATE_NOT_READY",
            "The completion certificate is available only after every seat is signed.",
        )
    return json.loads(row["certificate_json"])


def list_accounts(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute("SELECT * FROM accounts ORDER BY account_id").fetchall()
    return {
        "accounts": [_account_dict(row) for row in rows],
        "public_keys": {row["account_id"]: row["public_key_b64"] for row in rows},
    }
