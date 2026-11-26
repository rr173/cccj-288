"""SQLite persistence and transaction helpers.

The application uses one connection per request in autocommit mode and explicit
``BEGIN IMMEDIATE`` transactions for every state-changing operation.  This
serializes writers at the database layer and makes cancellation/signature races
deterministically all-or-nothing.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    account_id        TEXT PRIMARY KEY,
    public_key_b64    TEXT NOT NULL UNIQUE,
    display_name      TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agreements (
    agreement_id        TEXT PRIMARY KEY,
    initiator_account_id TEXT NOT NULL,
    title               TEXT NOT NULL,
    content             BLOB NOT NULL,
    content_sha256      TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('draft','active','completed','cancelled')),
    created_at          TEXT NOT NULL,
    sent_at             TEXT,
    completed_at        TEXT,
    cancelled_at        TEXT,
    cancel_reason       TEXT
);

CREATE TABLE IF NOT EXISTS seats (
    seat_id                  TEXT PRIMARY KEY,
    agreement_id             TEXT NOT NULL REFERENCES agreements(agreement_id),
    seat_key                 TEXT NOT NULL,
    label                    TEXT,
    stage                    INTEGER NOT NULL CHECK (stage >= 1),
    position                 INTEGER NOT NULL,
    original_account_id      TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN ('pending','signed','cancelled')),
    current_account_id       TEXT NOT NULL,
    current_delegation_id    TEXT,
    authority_generation     INTEGER NOT NULL DEFAULT 0,
    signature_id             TEXT,
    signed_by_account_id     TEXT,
    signed_at                TEXT,
    UNIQUE (agreement_id, seat_key),
    UNIQUE (agreement_id, position)
);

CREATE INDEX IF NOT EXISTS idx_seats_agreement ON seats(agreement_id, stage, position);

CREATE TABLE IF NOT EXISTS delegations (
    delegation_id             TEXT PRIMARY KEY,
    agreement_id              TEXT NOT NULL REFERENCES agreements(agreement_id),
    seat_id                   TEXT NOT NULL REFERENCES seats(seat_id),
    seq                       INTEGER NOT NULL,
    parent_delegation_id      TEXT,
    delegator_account_id      TEXT NOT NULL,
    delegatee_account_id      TEXT NOT NULL,
    operation_id              TEXT NOT NULL,
    revocation_id             TEXT,
    created_at                TEXT NOT NULL,
    revoked_at                TEXT
);

CREATE INDEX IF NOT EXISTS idx_delegations_seat ON delegations(seat_id, seq);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id             TEXT PRIMARY KEY,
    agreement_id              TEXT NOT NULL REFERENCES agreements(agreement_id),
    seat_id                   TEXT NOT NULL REFERENCES seats(seat_id),
    initiator_account_id      TEXT NOT NULL,
    operation_id              TEXT NOT NULL,
    revoked_head_delegation_id TEXT,
    revoked_chain_json        TEXT NOT NULL,
    created_at                TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id              TEXT PRIMARY KEY,
    agreement_id              TEXT NOT NULL REFERENCES agreements(agreement_id),
    seat_id                   TEXT NOT NULL REFERENCES seats(seat_id),
    operation_id              TEXT NOT NULL,
    account_id                TEXT NOT NULL,
    signer_public_key_b64     TEXT NOT NULL,
    challenge_bytes           BLOB NOT NULL,
    challenge_sha256          TEXT NOT NULL,
    body_sha256               TEXT NOT NULL,
    stage                     INTEGER NOT NULL,
    authority_generation      INTEGER NOT NULL,
    authority_hash            TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'issued'
                                  CHECK (status IN ('issued','consumed')),
    signature_id              TEXT UNIQUE,
    issued_at                 TEXT NOT NULL,
    consumed_at               TEXT
);

CREATE INDEX IF NOT EXISTS idx_challenges_seat ON challenges(seat_id, issued_at);

CREATE TABLE IF NOT EXISTS signatures (
    signature_id              TEXT PRIMARY KEY,
    agreement_id              TEXT NOT NULL REFERENCES agreements(agreement_id),
    seat_id                   TEXT NOT NULL UNIQUE REFERENCES seats(seat_id),
    challenge_id              TEXT NOT NULL UNIQUE REFERENCES challenges(challenge_id),
    operation_id              TEXT NOT NULL,
    stage                     INTEGER NOT NULL,
    body_sha256               TEXT NOT NULL,
    original_account_id       TEXT NOT NULL,
    actual_signer_account_id  TEXT NOT NULL,
    signer_public_key_b64     TEXT NOT NULL,
    signature_b64             TEXT NOT NULL,
    authority_generation      INTEGER NOT NULL,
    delegation_source_json    TEXT NOT NULL,
    stage_gate_json           TEXT NOT NULL,
    signed_at                 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    agreement_id        TEXT PRIMARY KEY REFERENCES agreements(agreement_id),
    certificate_id      TEXT NOT NULL UNIQUE,
    certificate_json    TEXT NOT NULL,
    certificate_sha256  TEXT NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    scope               TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    request_sha256      TEXT NOT NULL,
    status_code         INTEGER NOT NULL,
    content_type        TEXT NOT NULL,
    body                BLOB NOT NULL,
    headers_json        TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    PRIMARY KEY (scope, idempotency_key)
);

-- ---------------------------------------------------------------------------
-- Receivable settlement (应收款结算)
--
-- All money amounts are integer minor units (cents, 分).  Every state change
-- below happens inside a BEGIN IMMEDIATE transaction so concurrent receipts,
-- refunds, transfer confirmations and disbursements are equivalent to some
-- serial order.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS receivables (
    receivable_id           TEXT PRIMARY KEY,
    receivable_no           TEXT NOT NULL UNIQUE,
    agreement_id            TEXT NOT NULL REFERENCES agreements(agreement_id),
    operator_account_id     TEXT NOT NULL,
    debtor                  TEXT NOT NULL,
    original_creditor_id    TEXT NOT NULL,
    principal_cents         INTEGER NOT NULL CHECK (principal_cents > 0),
    remaining_cents         INTEGER NOT NULL CHECK (remaining_cents >= 0),
    status                  TEXT NOT NULL DEFAULT 'open'
                                  CHECK (status IN ('open','settled')),
    created_at              TEXT NOT NULL
);

-- One row per creditor currently (or historically) holding a slice of a
-- receivable's unrecovered principal.  Transfers move rows between accounts;
-- receipts reduce held_cents; refunds restore held_cents to the original
-- payee regardless of later transfers.
CREATE TABLE IF NOT EXISTS receivable_holdings (
    holding_id              TEXT PRIMARY KEY,
    receivable_id           TEXT NOT NULL REFERENCES receivables(receivable_id),
    account_id              TEXT NOT NULL,
    held_cents              INTEGER NOT NULL CHECK (held_cents >= 0),
    updated_at              TEXT NOT NULL,
    UNIQUE (receivable_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_holdings_account ON receivable_holdings(account_id);

CREATE TABLE IF NOT EXISTS transfer_applications (
    transfer_id             TEXT PRIMARY KEY,
    receivable_id           TEXT NOT NULL REFERENCES receivables(receivable_id),
    transferor_account_id   TEXT NOT NULL,
    transferee_account_id   TEXT NOT NULL,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
    agreement_id            TEXT NOT NULL UNIQUE REFERENCES agreements(agreement_id),
    status                  TEXT NOT NULL
                                  CHECK (status IN ('pending','effective','terminated')),
    terminated_reason       TEXT,
    effective_at            TEXT,
    terminated_at           TEXT,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transfers_receivable ON transfer_applications(receivable_id);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id              TEXT PRIMARY KEY,
    receivable_id           TEXT NOT NULL REFERENCES receivables(receivable_id),
    channel_serial_no       TEXT NOT NULL UNIQUE,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
    remaining_cents         INTEGER NOT NULL CHECK (remaining_cents >= 0),
    operator_account_id     TEXT NOT NULL,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_receivable ON receipts(receivable_id);

-- Immutable split lines of one receipt.  The account on a split line is the
-- creditor that received the share; later refunds always come back to these
-- same accounts even if the receivable was transferred afterwards.
CREATE TABLE IF NOT EXISTS receipt_allocations (
    allocation_id           TEXT PRIMARY KEY,
    receipt_id              TEXT NOT NULL REFERENCES receipts(receipt_id),
    account_id              TEXT NOT NULL,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents >= 0),
    reversed_cents          INTEGER NOT NULL DEFAULT 0 CHECK (reversed_cents >= 0),
    deduction_offset_cents  INTEGER NOT NULL DEFAULT 0 CHECK (deduction_offset_cents >= 0),
    net_credited_cents      INTEGER NOT NULL DEFAULT 0 CHECK (net_credited_cents >= 0),
    position                INTEGER NOT NULL,
    created_at              TEXT NOT NULL,
    UNIQUE (receipt_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_allocations_account ON receipt_allocations(account_id);

CREATE TABLE IF NOT EXISTS refunds (
    refund_id               TEXT PRIMARY KEY,
    receipt_id              TEXT NOT NULL REFERENCES receipts(receipt_id),
    channel_serial_no       TEXT NOT NULL UNIQUE,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
    operator_account_id     TEXT NOT NULL,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refunds_receipt ON refunds(receipt_id);

-- Immutable reversal lines of one refund, matched back to original split
-- lines.  Reversal never recomputes creditor ratios at refund time.
CREATE TABLE IF NOT EXISTS refund_reversals (
    reversal_id             TEXT PRIMARY KEY,
    refund_id               TEXT NOT NULL REFERENCES refunds(refund_id),
    allocation_id           TEXT NOT NULL REFERENCES receipt_allocations(allocation_id),
    account_id              TEXT NOT NULL,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
    clawback_from_balance   INTEGER NOT NULL CHECK (clawback_from_balance >= 0),
    clawback_to_deduction   INTEGER NOT NULL CHECK (clawback_to_deduction >= 0),
    position                INTEGER NOT NULL,
    created_at              TEXT NOT NULL
);

-- One cross-receivable settlement account per creditor.  Rows are created
-- lazily.  available_cents is immediately drawable; pending_deduction_cents
-- is the cumulative clawback debt that future allocations must absorb first.
CREATE TABLE IF NOT EXISTS settlement_accounts (
    account_id                  TEXT PRIMARY KEY,
    available_cents             INTEGER NOT NULL DEFAULT 0 CHECK (available_cents >= 0),
    pending_deduction_cents     INTEGER NOT NULL DEFAULT 0 CHECK (pending_deduction_cents >= 0),
    total_allocated_cents       INTEGER NOT NULL DEFAULT 0 CHECK (total_allocated_cents >= 0),
    total_clawback_cents        INTEGER NOT NULL DEFAULT 0 CHECK (total_clawback_cents >= 0),
    total_disbursed_cents       INTEGER NOT NULL DEFAULT 0 CHECK (total_disbursed_cents >= 0),
    updated_at                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disbursements (
    disbursement_id         TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL,
    amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
    note                    TEXT,
    operator_account_id     TEXT NOT NULL,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_disbursements_account ON disbursements(account_id);

-- Append-only double-entry-style movement journal for settlement accounts.
-- Every balance/deduction change writes one or more rows here, so balances
-- can be recomputed from the journal after a restart and reconciled.
CREATE TABLE IF NOT EXISTS settlement_ledger (
    ledger_id               TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL,
    event_type              TEXT NOT NULL CHECK (event_type IN (
                                'allocation','allocation_deduction_offset',
                                'refund_clawback_balance','refund_clawback_deduction',
                                'disbursement'
                            )),
    ref_type                TEXT NOT NULL CHECK (ref_type IN (
                                'receipt_allocation','refund_reversal','disbursement'
                            )),
    ref_id                  TEXT NOT NULL,
    delta_available         INTEGER NOT NULL,
    delta_deduction         INTEGER NOT NULL,
    balance_after           INTEGER NOT NULL,
    deduction_after         INTEGER NOT NULL,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_account ON settlement_ledger(account_id);
"""


def connect(database_path: str | Path) -> sqlite3.Connection:
    path = Path(database_path)
    if path.parent and str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(path),
        timeout=30.0,
        isolation_level=None,  # explicit BEGIN/COMMIT
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL is persistent for the database; setting it per connection is harmless.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextmanager
def immediate_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Serialize a write operation using SQLite BEGIN IMMEDIATE."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
