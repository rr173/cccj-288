"""Cryptographic and canonical-encoding helpers shared by server and verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("base64 value must be a string")
    return base64.b64decode(data.encode("ascii"), validate=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_id(data: bytes) -> str:
    return f"sha256:{sha256_hex(data)}"


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic JSON bytes used for hashes and idempotency fingerprints."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def raw_public_key_b64(public_key: Ed25519PublicKey) -> str:
    return b64e(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_key_from_b64(public_key_b64: str) -> Ed25519PublicKey:
    raw = b64d(public_key_b64)
    if len(raw) != 32:
        raise ValueError("Ed25519 raw public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_ed25519_b64(public_key_b64: str, message: bytes, signature_b64: str) -> None:
    """Raise InvalidSignature/ValueError if the Ed25519 signature is invalid."""
    public_key = public_key_from_b64(public_key_b64)
    signature = b64d(signature_b64)
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        raise
