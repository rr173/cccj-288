"""Client-side key storage and HTTP helpers.

Private Ed25519 keys are generated and read only by this request-side code.
The server receives only the raw 32-byte public key encoded as base64.
"""

from __future__ import annotations

import base64
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def operation_id(prefix: str = "op") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


class ApiCallError(RuntimeError):
    def __init__(self, method: str, path: str, status_code: int, body: Any):
        code = None
        message = None
        if isinstance(body, dict):
            error = body.get("error") or {}
            code = error.get("code")
            message = error.get("message")
        super().__init__(f"{method} {path} -> {status_code} {code}: {message or body}")
        self.method = method
        self.path = path
        self.status_code = status_code
        self.body = body
        self.code = code


class KeyStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _private_path(self, account_id: str) -> Path:
        return self.directory / f"{account_id}.ed25519.pem"

    def _public_path(self, account_id: str) -> Path:
        return self.directory / f"{account_id}.public.b64"

    def load_or_create(self, account_id: str) -> "LocalSigner":
        path = self._private_path(account_id)
        if path.exists():
            private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                raise TypeError(f"{path} is not an Ed25519 private key")
        else:
            private_key = Ed25519PrivateKey.generate()
            path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            path.chmod(0o600)

        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_b64 = b64e(public_raw)
        self._public_path(account_id).write_text(public_b64 + "\n", encoding="ascii")
        return LocalSigner(account_id, private_key, public_b64)

    def load(self, account_id: str) -> "LocalSigner":
        path = self._private_path(account_id)
        if not path.exists():
            raise FileNotFoundError(f"No local private key for {account_id}: {path}")
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(private_key, Ed25519PrivateKey)
        public_b64 = b64e(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        return LocalSigner(account_id, private_key, public_b64)


class LocalSigner:
    def __init__(self, account_id: str, private_key: Ed25519PrivateKey, public_key_b64: str):
        self.account_id = account_id
        self.private_key = private_key
        self.public_key_b64 = public_key_b64

    def sign_exact_bytes(self, raw_challenge_bytes: bytes) -> str:
        # This deliberately signs the exact HTTP response bytes, not a
        # re-serialized JSON object.
        return b64e(self.private_key.sign(raw_challenge_bytes))


class SigningClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=timeout)

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> "SigningClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request_json(
        self,
        method: str,
        path: str,
        json_body: Optional[dict[str, Any]] = None,
        expected: Optional[set[int]] = None,
    ) -> Any:
        response = self.http.request(method, path, json=json_body)
        if expected is not None and response.status_code not in expected:
            raise ApiCallError(method, path, response.status_code, _safe_json(response))
        if response.status_code >= 400:
            raise ApiCallError(method, path, response.status_code, _safe_json(response))
        if response.content:
            return response.json()
        return None

    def health(self) -> dict[str, str]:
        return self.request_json("GET", "/health")

    def register(self, signer: LocalSigner, op_id: Optional[str] = None) -> dict[str, Any]:
        return self.request_json(
            "POST",
            "/accounts",
            {
                "operation_id": op_id or operation_id("account"),
                "account_id": signer.account_id,
                "public_key_b64": signer.public_key_b64,
            },
        )

    def accounts(self) -> dict[str, Any]:
        return self.request_json("GET", "/accounts")

    def create_agreement(
        self,
        *,
        initiator: str,
        title: str,
        content_text: Optional[str] = None,
        content_base64: Optional[str] = None,
        seats: list[dict[str, Any]],
        op_id: Optional[str] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "operation_id": op_id or operation_id("create"),
            "initiator_account_id": initiator,
            "title": title,
            "seats": seats,
        }
        if content_text is not None:
            body["content_text"] = content_text
        if content_base64 is not None:
            body["content_base64"] = content_base64
        return self.request_json("POST", "/agreements", body)

    def send(self, agreement_id: str, initiator: str, op_id: Optional[str] = None) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/agreements/{agreement_id}/send",
            {"operation_id": op_id or operation_id("send"), "initiator_account_id": initiator},
        )

    def get_agreement(self, agreement_id: str) -> dict[str, Any]:
        return self.request_json("GET", f"/agreements/{agreement_id}")

    def cancel(
        self, agreement_id: str, initiator: str, reason: str = "", op_id: Optional[str] = None
    ) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/agreements/{agreement_id}/cancellation",
            {
                "operation_id": op_id or operation_id("cancel"),
                "initiator_account_id": initiator,
                "reason": reason,
            },
        )

    def delegate(
        self,
        agreement_id: str,
        seat_id: str,
        actor: str,
        delegatee: str,
        op_id: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/agreements/{agreement_id}/seats/{seat_id}/delegations",
            {
                "operation_id": op_id or operation_id("delegate"),
                "actor_account_id": actor,
                "delegatee_account_id": delegatee,
            },
        )

    def revoke(
        self, agreement_id: str, seat_id: str, initiator: str, op_id: Optional[str] = None
    ) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/agreements/{agreement_id}/seats/{seat_id}/revocations",
            {
                "operation_id": op_id or operation_id("revoke"),
                "initiator_account_id": initiator,
            },
        )

    def issue_challenge(
        self, agreement_id: str, seat_id: str, account_id: str, op_id: Optional[str] = None
    ) -> httpx.Response:
        op = op_id or operation_id("challenge")
        response = self.http.post(
            f"/agreements/{agreement_id}/seats/{seat_id}/challenges",
            json={"operation_id": op, "account_id": account_id},
        )
        if response.status_code >= 400:
            raise ApiCallError(
                "POST",
                f"/agreements/{agreement_id}/seats/{seat_id}/challenges",
                response.status_code,
                _safe_json(response),
            )
        return response

    def submit_signature(
        self, challenge_id: str, signature_b64: str, op_id: Optional[str] = None
    ) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/challenges/{challenge_id}/signature",
            {
                "operation_id": op_id or operation_id("sign"),
                "signature_b64": signature_b64,
            },
        )

    def sign_challenge(
        self,
        agreement_id: str,
        seat_id: str,
        signer: LocalSigner,
        challenge_op: Optional[str] = None,
        signature_op: Optional[str] = None,
    ) -> dict[str, Any]:
        challenge_response = self.issue_challenge(
            agreement_id, seat_id, signer.account_id, challenge_op
        )
        challenge_id = challenge_response.headers["x-challenge-id"]
        signature_b64 = signer.sign_exact_bytes(challenge_response.content)
        return self.submit_signature(challenge_id, signature_b64, signature_op)

    def certificate(self, agreement_id: str) -> dict[str, Any]:
        return self.request_json("GET", f"/agreements/{agreement_id}/certificate")


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return response.text
