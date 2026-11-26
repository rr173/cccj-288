"""Persistent idempotency helpers."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from fastapi import Response

from .db import immediate_transaction
from .errors import ApiError
from .security import canonical_json_bytes, canonical_json_text, new_id, sha256_hex, utc_now


@dataclass
class OpResult:
    status_code: int
    body: Any = None
    raw_body: Optional[bytes] = None
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)

    def to_response(self) -> Response:
        if self.raw_body is not None:
            content = self.raw_body
        else:
            content = canonical_json_bytes(self.body if self.body is not None else {})
        return Response(
            content=content,
            status_code=self.status_code,
            media_type=self.content_type,
            headers=self.headers,
        )


def _request_hash(fingerprint: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(fingerprint))


def _find(conn: sqlite3.Connection, scope: str, key: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM idempotency_records WHERE scope = ? AND idempotency_key = ?",
        (scope, key),
    ).fetchone()


def _replay(row: sqlite3.Row, request_hash: str, scope: str, key: str) -> OpResult:
    if row["request_sha256"] != request_hash:
        raise ApiError(
            409,
            "IDEMPOTENCY_REQUEST_CONFLICT",
            "This operation ID was first used with different request content.",
            {"scope": scope, "operation_id": key},
        )
    return OpResult(
        status_code=row["status_code"],
        raw_body=bytes(row["body"]),
        content_type=row["content_type"],
        headers=json.loads(row["headers_json"] or "{}"),
    )


def _store_api_error(
    conn: sqlite3.Connection,
    scope: str,
    key: str,
    request_hash: str,
    exc: ApiError,
) -> None:
    if exc.code == "IDEMPOTENCY_REQUEST_CONFLICT":
        return
    error_body = {
        "error": {
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        }
    }
    body = canonical_json_bytes(error_body)
    try:
        with immediate_transaction(conn):
            # INSERT OR IGNORE handles a concurrent identical request that won
            # the race to record its terminal result.
            conn.execute(
                """
                INSERT OR IGNORE INTO idempotency_records (
                    scope, idempotency_key, request_sha256, status_code,
                    content_type, body, headers_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope,
                    key,
                    request_hash,
                    exc.status_code,
                    "application/json",
                    body,
                    "{}",
                    utc_now(),
                ),
            )
    except sqlite3.Error:
        # Idempotency error persistence must not mask the original API error.
        pass


def idempotent(
    conn: sqlite3.Connection,
    scope: str,
    operation_id: str,
    fingerprint: dict[str, Any],
    producer: Callable[[sqlite3.Connection], OpResult],
) -> OpResult:
    if not operation_id or not operation_id.strip():
        raise ApiError(400, "MISSING_OPERATION_ID", "operation_id is required")

    request_hash = _request_hash(fingerprint)
    existing = _find(conn, scope, operation_id)
    if existing is not None:
        return _replay(existing, request_hash, scope, operation_id)

    try:
        with immediate_transaction(conn):
            # Re-check inside the serialized write transaction.
            existing = _find(conn, scope, operation_id)
            if existing is not None:
                return _replay(existing, request_hash, scope, operation_id)

            result = producer(conn)
            if result.raw_body is None:
                result.raw_body = canonical_json_bytes(
                    result.body if result.body is not None else {}
                )
                result.content_type = "application/json"

            conn.execute(
                """
                INSERT INTO idempotency_records (
                    scope, idempotency_key, request_sha256, status_code,
                    content_type, body, headers_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope,
                    operation_id,
                    request_hash,
                    result.status_code,
                    result.content_type,
                    result.raw_body,
                    canonical_json_text(result.headers or {}),
                    utc_now(),
                ),
            )
            return result
    except ApiError as exc:
        _store_api_error(conn, scope, operation_id, request_hash, exc)
        raise


def new_operation_id(prefix: str = "op") -> str:
    return new_id(prefix)
