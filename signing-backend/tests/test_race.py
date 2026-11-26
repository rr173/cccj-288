from __future__ import annotations

import base64
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from signing_backend.db import connect
from signing_backend.idempotency import OpResult, idempotent
from signing_backend.main import create_app
from signing_backend.schemas import CancelRequest, SignatureRequest
from signing_backend import service


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _make_signer() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_b64 = b64e(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return private_key, public_b64


def test_cancellation_versus_last_signature_race(tmp_path: Path) -> None:
    db_path = tmp_path / "race.db"
    app = create_app(db_path)

    private_key, public_b64 = _make_signer()
    run_id = uuid.uuid4().hex

    with TestClient(app) as client:
        reg = client.post(
            "/accounts",
            json={
                "operation_id": f"race-register-{run_id}",
                "account_id": "race_signer",
                "public_key_b64": public_b64,
            },
        )
        assert reg.status_code in (200, 201), reg.text

        created = client.post(
            "/agreements",
            json={
                "operation_id": f"race-create-{run_id}",
                "initiator_account_id": "race_initiator",
                "title": "竞争测试",
                "content_text": "取消与最后签名竞争\n",
                "seats": [
                    {"seat_key": "only", "original_account_id": "race_signer", "stage": 1}
                ],
            },
        )
        assert created.status_code == 201, created.text
        aid = created.json()["agreement_id"]
        sid = created.json()["seats"][0]["seat_id"]
        sent = client.post(
            f"/agreements/{aid}/send",
            json={
                "operation_id": f"race-send-{run_id}",
                "initiator_account_id": "race_initiator",
            },
        )
        assert sent.status_code == 200, sent.text

        challenge = client.post(
            f"/agreements/{aid}/seats/{sid}/challenges",
            json={
                "operation_id": f"race-challenge-{run_id}",
                "account_id": "race_signer",
            },
        )
        assert challenge.status_code == 201, challenge.text
        chid = challenge.headers["x-challenge-id"]
        signature_b64 = b64e(private_key.sign(challenge.content))

    barrier = threading.Barrier(2)

    def sign_worker() -> tuple[str, str | None]:
        barrier.wait(timeout=10)
        conn = connect(db_path)
        try:
            data = SignatureRequest(
                operation_id=f"race-sign-op-{run_id}",
                signature_b64=signature_b64,
            )

            def produce(c) -> OpResult:
                return OpResult(201, service.submit_signature_tx(c, chid, data))

            result = idempotent(
                conn,
                "signature.submit",
                data.operation_id,
                {"challenge_id": chid, "body": data.model_dump()},
                produce,
            )
            return "signed", result.body["signature_id"]
        except Exception as exc:  # noqa: BLE001 - test records race loser code
            code = getattr(exc, "code", exc.__class__.__name__)
            return "sign_error", code
        finally:
            conn.close()

    def cancel_worker() -> tuple[str, str | None]:
        barrier.wait(timeout=10)
        conn = connect(db_path)
        try:
            data = CancelRequest(
                operation_id=f"race-cancel-op-{run_id}",
                initiator_account_id="race_initiator",
                reason="race",
            )

            def produce(c) -> OpResult:
                return OpResult(200, service.cancel_agreement_tx(c, aid, data))

            result = idempotent(
                conn,
                "agreement.cancel",
                data.operation_id,
                {"agreement_id": aid, "body": data.model_dump()},
                produce,
            )
            return "cancelled", result.body["status"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", exc.__class__.__name__)
            return "cancel_error", code
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        sign_future = pool.submit(sign_worker)
        cancel_future = pool.submit(cancel_worker)
        sign_outcome = sign_future.result(timeout=30)
        cancel_outcome = cancel_future.result(timeout=30)

    # Exactly one terminal operation wins.
    assert sign_outcome[0] == "signed" or cancel_outcome[0] == "cancelled"
    assert not (sign_outcome[0] == "signed" and cancel_outcome[0] == "cancelled")

    conn = connect(db_path)
    try:
        agreement = conn.execute(
            "SELECT status FROM agreements WHERE agreement_id = ?", (aid,)
        ).fetchone()
        signature_count = conn.execute(
            "SELECT COUNT(*) AS n FROM signatures WHERE agreement_id = ?", (aid,)
        ).fetchone()["n"]
        certificate = conn.execute(
            "SELECT 1 FROM certificates WHERE agreement_id = ?", (aid,)
        ).fetchone()

        if sign_outcome[0] == "signed":
            assert cancel_outcome == ("cancel_error", "AGREEMENT_COMPLETED")
            assert agreement["status"] == "completed"
            assert signature_count == 1
            assert certificate is not None
        else:
            assert cancel_outcome[0] == "cancelled"
            assert sign_outcome == ("sign_error", "AGREEMENT_NOT_ACTIVE")
            assert agreement["status"] == "cancelled"
            assert signature_count == 0
            assert certificate is None
    finally:
        conn.close()


def test_repeated_cancellation_signature_races_are_always_consistent(tmp_path: Path) -> None:
    """Run several races to catch obvious transaction isolation regressions."""
    for index in range(8):
        db_path = tmp_path / f"race-{index}.db"
        app = create_app(db_path)
        private_key, public_b64 = _make_signer()
        with TestClient(app) as client:
            client.post(
                "/accounts",
                json={
                    "operation_id": f"reg-{index}",
                    "account_id": "u",
                    "public_key_b64": public_b64,
                },
            )
            created = client.post(
                "/agreements",
                json={
                    "operation_id": f"create-{index}",
                    "initiator_account_id": "i",
                    "title": "t",
                    "content_text": f"body {index}",
                    "seats": [{"seat_key": "s", "original_account_id": "u", "stage": 1}],
                },
            ).json()
            aid = created["agreement_id"]
            sid = created["seats"][0]["seat_id"]
            client.post(
                f"/agreements/{aid}/send",
                json={"operation_id": f"send-{index}", "initiator_account_id": "i"},
            )
            challenge = client.post(
                f"/agreements/{aid}/seats/{sid}/challenges",
                json={"operation_id": f"chal-{index}", "account_id": "u"},
            )
            chid = challenge.headers["x-challenge-id"]
            sig = b64e(private_key.sign(challenge.content))

        barrier = threading.Barrier(2)

        def signer() -> bool:
            barrier.wait()
            conn = connect(db_path)
            try:
                data = SignatureRequest(operation_id=f"sign-{index}", signature_b64=sig)
                try:
                    idempotent(
                        conn,
                        "signature.submit",
                        data.operation_id,
                        {"challenge_id": chid, "body": data.model_dump()},
                        lambda c: OpResult(201, service.submit_signature_tx(c, chid, data)),
                    )
                    return True
                except Exception:
                    return False
            finally:
                conn.close()

        def canceller() -> bool:
            barrier.wait()
            conn = connect(db_path)
            try:
                data = CancelRequest(operation_id=f"cancel-{index}", initiator_account_id="i")
                try:
                    idempotent(
                        conn,
                        "agreement.cancel",
                        data.operation_id,
                        {"agreement_id": aid, "body": data.model_dump()},
                        lambda c: OpResult(200, service.cancel_agreement_tx(c, aid, data)),
                    )
                    return True
                except Exception:
                    return False
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            sign_future = pool.submit(signer)
            cancel_future = pool.submit(canceller)
            s = sign_future.result(timeout=30)
            c = cancel_future.result(timeout=30)
        assert s is not c  # exactly one wins

        conn = connect(db_path)
        try:
            status = conn.execute(
                "SELECT status FROM agreements WHERE agreement_id=?", (aid,)
            ).fetchone()["status"]
            sigs = conn.execute(
                "SELECT COUNT(*) n FROM signatures WHERE agreement_id=?", (aid,)
            ).fetchone()["n"]
            if status == "completed":
                assert sigs == 1
            else:
                assert status == "cancelled" and sigs == 0
        finally:
            conn.close()
