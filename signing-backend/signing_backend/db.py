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
