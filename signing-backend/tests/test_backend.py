from __future__ import annotations

import base64
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from signing_backend.main import create_app
from signing_backend.verifier import verify_certificate


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(tmp_path / "signing.db")
    with TestClient(app) as test_client:
        yield test_client


class Wallet:
    def __init__(self) -> None:
        self.private_keys: dict[str, Ed25519PrivateKey] = {}
        self.public_keys: dict[str, str] = {}

    def add(self, account_id: str) -> Ed25519PrivateKey:
        private_key = Ed25519PrivateKey.generate()
        raw_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.private_keys[account_id] = private_key
        self.public_keys[account_id] = b64e(raw_public)
        return private_key

    def sign(self, account_id: str, raw_challenge: bytes) -> str:
        return b64e(self.private_keys[account_id].sign(raw_challenge))


@pytest.fixture()
def wallet(client: TestClient) -> Wallet:
    wallet = Wallet()
    for account_id in ["alice", "bob", "carol", "dave", "owner", "delegate_a", "delegate_b"]:
        wallet.add(account_id)
        response = client.post(
            "/accounts",
            json={
                "operation_id": f"register-{account_id}",
                "account_id": account_id,
                "public_key_b64": wallet.public_keys[account_id],
            },
        )
        assert response.status_code in (200, 201), response.text
    return wallet


def create_sent_agreement(
    client: TestClient,
    wallet: Wallet,
    *,
    operation_id: str | None = None,
    seats: list[dict[str, Any]] | None = None,
    initiator: str = "initiator",
    content_text: str = "测试协议正文\n",
) -> dict[str, Any]:
    seats = seats or [
        {"seat_key": "alice", "original_account_id": "alice", "stage": 1},
        {"seat_key": "bob", "original_account_id": "bob", "stage": 1},
        {"seat_key": "carol", "original_account_id": "carol", "stage": 2},
    ]
    op = operation_id or f"create-{uuid.uuid4().hex}"
    response = client.post(
        "/agreements",
        json={
            "operation_id": op,
            "initiator_account_id": initiator,
            "title": "测试协议",
            "content_text": content_text,
            "seats": seats,
        },
    )
    assert response.status_code == 201, response.text
    agreement = response.json()
    send = client.post(
        f"/agreements/{agreement['agreement_id']}/send",
        json={"operation_id": f"send-{op}", "initiator_account_id": initiator},
    )
    assert send.status_code == 200, send.text
    return send.json()


def issue_and_sign(
    client: TestClient,
    wallet: Wallet,
    agreement_id: str,
    seat_id: str,
    account_id: str,
    *,
    operation_id: str | None = None,
) -> dict[str, Any]:
    op = operation_id or uuid.uuid4().hex
    challenge_response = client.post(
        f"/agreements/{agreement_id}/seats/{seat_id}/challenges",
        json={"operation_id": f"challenge-{op}", "account_id": account_id},
    )
    assert challenge_response.status_code == 201, challenge_response.text
    challenge_id = challenge_response.headers["x-challenge-id"]
    signature = wallet.sign(account_id, challenge_response.content)
    sign_response = client.post(
        f"/challenges/{challenge_id}/signature",
        json={"operation_id": f"sign-{op}", "signature_b64": signature},
    )
    assert sign_response.status_code == 201, sign_response.text
    return sign_response.json()


def test_two_stage_flow_and_independent_verification(
    client: TestClient, wallet: Wallet
) -> None:
    agreement = create_sent_agreement(client, wallet)
    aid = agreement["agreement_id"]
    seats = {seat["seat_key"]: seat for seat in agreement["seats"]}

    # Stage 2 is locked before stage 1 has any signature.
    early = client.post(
        f"/agreements/{aid}/seats/{seats['carol']['seat_id']}/challenges",
        json={"operation_id": "early-carol", "account_id": "carol"},
    )
    assert early.status_code == 409
    assert early.json()["error"]["code"] == "STAGE_LOCKED"

    issue_and_sign(client, wallet, aid, seats["alice"]["seat_id"], "alice", operation_id="alice")

    # One of two parallel stage-1 seats is not enough.
    still_locked = client.post(
        f"/agreements/{aid}/seats/{seats['carol']['seat_id']}/challenges",
        json={"operation_id": "still-early-carol", "account_id": "carol"},
    )
    assert still_locked.status_code == 409
    assert still_locked.json()["error"]["code"] == "STAGE_LOCKED"

    issue_and_sign(client, wallet, aid, seats["bob"]["seat_id"], "bob", operation_id="bob")
    issue_and_sign(client, wallet, aid, seats["carol"]["seat_id"], "carol", operation_id="carol")

    # The default agreement has three seats, all now signed.
    cert_response = client.get(f"/agreements/{aid}/certificate")
    assert cert_response.status_code == 200, cert_response.text
    certificate = cert_response.json()
    registry = client.get("/accounts").json()
    report = verify_certificate(certificate, registry=registry)
    assert report["valid"], report["errors"]
    assert [seat["actual_signer_account_id"] for seat in report["seats"]] == [
        "alice",
        "bob",
        "carol",
    ]

    # Tampering with body must fail independent verification.
    tampered = dict(certificate)
    tampered_body = dict(certificate["body"])
    tampered_body["data"] = b64e(b"tampered body")
    tampered["body"] = tampered_body
    bad_report = verify_certificate(tampered, registry=registry)
    assert not bad_report["valid"]


def test_delegation_cycle_revocation_and_stale_challenge(
    client: TestClient, wallet: Wallet
) -> None:
    agreement = create_sent_agreement(
        client,
        wallet,
        operation_id="delegation-agreement",
        seats=[{"seat_key": "one", "original_account_id": "owner", "stage": 1}],
        initiator="initiator-delegation",
    )
    aid = agreement["agreement_id"]
    sid = agreement["seats"][0]["seat_id"]

    for body in [
        {
            "operation_id": "del-o-a",
            "actor_account_id": "owner",
            "delegatee_account_id": "delegate_a",
        }
    ]:
        response = client.post(f"/agreements/{aid}/seats/{sid}/delegations", json=body)
        assert response.status_code == 201, response.text

    delegation_view = client.get(f"/agreements/{aid}/seats/{sid}/delegations")
    assert delegation_view.status_code == 200
    view = delegation_view.json()
    assert view["current_account_id"] == "delegate_a"
    assert [link["delegatee_account_id"] for link in view["active_chain"]] == ["delegate_a"]

    # A gets a challenge while authorized, but does not submit it yet.
    challenge = client.post(
        f"/agreements/{aid}/seats/{sid}/challenges",
        json={"operation_id": "old-a-challenge", "account_id": "delegate_a"},
    )
    assert challenge.status_code == 201, challenge.text
    old_challenge_id = challenge.headers["x-challenge-id"]
    old_signature = wallet.sign("delegate_a", challenge.content)

    second = client.post(
        f"/agreements/{aid}/seats/{sid}/delegations",
        json={
            "operation_id": "del-a-b",
            "actor_account_id": "delegate_a",
            "delegatee_account_id": "delegate_b",
        },
    )
    assert second.status_code == 201, second.text

    cycle = client.post(
        f"/agreements/{aid}/seats/{sid}/delegations",
        json={
            "operation_id": "cycle-b-owner",
            "actor_account_id": "delegate_b",
            "delegatee_account_id": "owner",
        },
    )
    assert cycle.status_code == 409
    assert cycle.json()["error"]["code"] == "DELEGATION_CYCLE"

    unauthorized = client.post(
        f"/agreements/{aid}/seats/{sid}/delegations",
        json={
            "operation_id": "old-a-delegates",
            "actor_account_id": "delegate_a",
            "delegatee_account_id": "carol",
        },
    )
    assert unauthorized.status_code == 403
    assert unauthorized.json()["error"]["code"] == "NOT_CURRENT_AUTHORITY"

    revoke = client.post(
        f"/agreements/{aid}/seats/{sid}/revocations",
        json={"operation_id": "revoke-1", "initiator_account_id": "initiator-delegation"},
    )
    assert revoke.status_code == 201, revoke.text

    # Delegate back to the same A. The generation must make the old challenge dead.
    redelegate = client.post(
        f"/agreements/{aid}/seats/{sid}/delegations",
        json={
            "operation_id": "redelete-a",
            "actor_account_id": "owner",
            "delegatee_account_id": "delegate_a",
        },
    )
    assert redelegate.status_code == 201, redelegate.text

    stale = client.post(
        f"/challenges/{old_challenge_id}/signature",
        json={"operation_id": "stale-submit", "signature_b64": old_signature},
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "AUTHORITY_STALE"

    new_challenge = client.post(
        f"/agreements/{aid}/seats/{sid}/challenges",
        json={"operation_id": "new-a-challenge", "account_id": "delegate_a"},
    )
    assert new_challenge.status_code == 201, new_challenge.text
    new_challenge_id = new_challenge.headers["x-challenge-id"]
    new_signature = wallet.sign("delegate_a", new_challenge.content)
    new_sign_body = {"operation_id": "new-a-signature-op", "signature_b64": new_signature}
    first_new_sign = client.post(
        f"/challenges/{new_challenge_id}/signature", json=new_sign_body
    )
    assert first_new_sign.status_code == 201, first_new_sign.text
    assert first_new_sign.json()["actual_signer_account_id"] == "delegate_a"

    # Exact same operation ID/content returns the first stored result.
    retry = client.post(f"/challenges/{new_challenge_id}/signature", json=new_sign_body)
    assert retry.status_code == 201
    assert retry.json()["signature_id"] == first_new_sign.json()["signature_id"]

    cert = client.get(f"/agreements/{aid}/certificate")
    assert cert.status_code == 200, cert.text
    report = verify_certificate(cert.json(), registry=client.get("/accounts").json())
    assert report["valid"], report["errors"]

    # A completed signature cannot be revoked or moved by a later delegation.
    revoke_completed = client.post(
        f"/agreements/{aid}/seats/{sid}/revocations",
        json={
            "operation_id": "revoke-completed",
            "initiator_account_id": "initiator-delegation",
        },
    )
    assert revoke_completed.status_code == 409
    assert revoke_completed.json()["error"]["code"] in {
        "AGREEMENT_NOT_ACTIVE",
        "SEAT_NOT_PENDING",
    }

    delegate_completed = client.post(
        f"/agreements/{aid}/seats/{sid}/delegations",
        json={
            "operation_id": "delegate-completed",
            "actor_account_id": "delegate_a",
            "delegatee_account_id": "bob",
        },
    )
    assert delegate_completed.status_code == 409
    assert delegate_completed.json()["error"]["code"] in {
        "AGREEMENT_NOT_ACTIVE",
        "SEAT_NOT_PENDING",
    }


def test_same_delegatee_must_confirm_each_seat_separately(
    client: TestClient, wallet: Wallet
) -> None:
    agreement = create_sent_agreement(
        client,
        wallet,
        operation_id="multi-seat-delegatee",
        seats=[
            {"seat_key": "seat-o", "original_account_id": "owner", "stage": 1},
            {"seat_key": "seat-b", "original_account_id": "bob", "stage": 1},
        ],
    )
    aid = agreement["agreement_id"]
    seats = {seat["seat_key"]: seat["seat_id"] for seat in agreement["seats"]}

    for seat_key, original in [("seat-o", "owner"), ("seat-b", "bob")]:
        response = client.post(
            f"/agreements/{aid}/seats/{seats[seat_key]}/delegations",
            json={
                "operation_id": f"delegate-{seat_key}",
                "actor_account_id": original,
                "delegatee_account_id": "delegate_a",
            },
        )
        assert response.status_code == 201, response.text

    ch1 = client.post(
        f"/agreements/{aid}/seats/{seats['seat-o']}/challenges",
        json={"operation_id": "challenge-o", "account_id": "delegate_a"},
    )
    ch1_id = ch1.headers["x-challenge-id"]
    sig1 = wallet.sign("delegate_a", ch1.content)
    first = client.post(
        f"/challenges/{ch1_id}/signature",
        json={"operation_id": "sign-o", "signature_b64": sig1},
    )
    assert first.status_code == 201, first.text

    # While the agreement is still active because seat-b is pending, the
    # already completed seat-o itself can no longer be delegated or revoked.
    delegate_signed_seat = client.post(
        f"/agreements/{aid}/seats/{seats['seat-o']}/delegations",
        json={
            "operation_id": "delegate-signed-o",
            "actor_account_id": "delegate_a",
            "delegatee_account_id": "carol",
        },
    )
    assert delegate_signed_seat.status_code == 409
    assert delegate_signed_seat.json()["error"]["code"] == "SEAT_NOT_PENDING"

    revoke_signed_seat = client.post(
        f"/agreements/{aid}/seats/{seats['seat-o']}/revocations",
        json={
            "operation_id": "revoke-signed-o",
            "initiator_account_id": "initiator",
        },
    )
    assert revoke_signed_seat.status_code == 409
    assert revoke_signed_seat.json()["error"]["code"] == "SEAT_NOT_PENDING"

    ch2 = client.post(
        f"/agreements/{aid}/seats/{seats['seat-b']}/challenges",
        json={"operation_id": "challenge-b", "account_id": "delegate_a"},
    )
    ch2_id = ch2.headers["x-challenge-id"]

    # One Ed25519 signature over the first seat's distinct challenge bytes
    # cannot fill the second seat.
    reused = client.post(
        f"/challenges/{ch2_id}/signature",
        json={"operation_id": "reuse-signature", "signature_b64": sig1},
    )
    assert reused.status_code == 422
    assert reused.json()["error"]["code"] == "INVALID_SIGNATURE"

    sig2 = wallet.sign("delegate_a", ch2.content)
    second = client.post(
        f"/challenges/{ch2_id}/signature",
        json={"operation_id": "sign-b", "signature_b64": sig2},
    )
    assert second.status_code == 201, second.text
    assert first.json()["signature_id"] != second.json()["signature_id"]

    cert = client.get(f"/agreements/{aid}/certificate").json()
    report = verify_certificate(cert, registry=client.get("/accounts").json())
    assert report["valid"], report["errors"]
    assert [seat["actual_signer_account_id"] for seat in report["seats"]] == [
        "delegate_a",
        "delegate_a",
    ]
    assert len({seat["signature_valid"] for seat in report["seats"]}) == 1


def test_body_change_means_cancel_and_new_agreement(
    client: TestClient, wallet: Wallet
) -> None:
    old_body = "旧正文：金额为壹元。\n"
    old = create_sent_agreement(
        client,
        wallet,
        operation_id="body-v1",
        content_text=old_body,
        seats=[
            {"seat_key": "alice", "original_account_id": "alice", "stage": 1},
            {"seat_key": "bob", "original_account_id": "bob", "stage": 1},
        ],
    )
    old_aid = old["agreement_id"]
    old_sid = old["seats"][0]["seat_id"]

    old_challenge = client.post(
        f"/agreements/{old_aid}/seats/{old_sid}/challenges",
        json={"operation_id": "v1-challenge", "account_id": "alice"},
    )
    old_signature = wallet.sign("alice", old_challenge.content)
    signed = client.post(
        f"/challenges/{old_challenge.headers['x-challenge-id']}/signature",
        json={"operation_id": "v1-sign", "signature_b64": old_signature},
    )
    assert signed.status_code == 201, signed.text

    cancelled = client.post(
        f"/agreements/{old_aid}/cancellation",
        json={"operation_id": "cancel-v1", "initiator_account_id": "initiator"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    new_body = "新正文：金额为贰元。\n"
    new = create_sent_agreement(
        client,
        wallet,
        operation_id="body-v2",
        content_text=new_body,
        seats=[
            {"seat_key": "alice", "original_account_id": "alice", "stage": 1},
            {"seat_key": "bob", "original_account_id": "bob", "stage": 1},
        ],
    )
    new_aid = new["agreement_id"]
    new_sid = new["seats"][0]["seat_id"]
    new_challenge = client.post(
        f"/agreements/{new_aid}/seats/{new_sid}/challenges",
        json={"operation_id": "v2-challenge", "account_id": "alice"},
    )
    new_challenge_id = new_challenge.headers["x-challenge-id"]

    # The old signature is valid for old challenge bytes/body only; it cannot
    # count as confirmation of the new body.
    reused_old_signature = client.post(
        f"/challenges/{new_challenge_id}/signature",
        json={"operation_id": "reuse-old-body-signature", "signature_b64": old_signature},
    )
    assert reused_old_signature.status_code == 422
    assert reused_old_signature.json()["error"]["code"] == "INVALID_SIGNATURE"

    new_signature = wallet.sign("alice", new_challenge.content)
    alice_new = client.post(
        f"/challenges/{new_challenge_id}/signature",
        json={"operation_id": "v2-alice-sign", "signature_b64": new_signature},
    )
    assert alice_new.status_code == 201, alice_new.text
    issue_and_sign(
        client,
        wallet,
        new_aid,
        new["seats"][1]["seat_id"],
        "bob",
        operation_id="v2-bob",
    )

    cert = client.get(f"/agreements/{new_aid}/certificate").json()
    registry = client.get("/accounts").json()
    assert verify_certificate(
        cert, registry=registry, expected_body=new_body.encode()
    )["valid"]
    old_body_report = verify_certificate(
        cert, registry=registry, expected_body=old_body.encode()
    )
    assert not old_body_report["valid"]


def test_one_challenge_cannot_produce_second_fact(
    client: TestClient, wallet: Wallet
) -> None:
    agreement = create_sent_agreement(
        client,
        wallet,
        operation_id="one-shot",
        seats=[{"seat_key": "alice-only", "original_account_id": "alice", "stage": 1}],
    )
    aid = agreement["agreement_id"]
    sid = agreement["seats"][0]["seat_id"]

    challenge = client.post(
        f"/agreements/{aid}/seats/{sid}/challenges",
        json={"operation_id": "chal-one", "account_id": "alice"},
    )
    chid = challenge.headers["x-challenge-id"]
    sig = wallet.sign("alice", challenge.content)
    body = {"operation_id": "sig-one", "signature_b64": sig}

    first = client.post(f"/challenges/{chid}/signature", json=body)
    assert first.status_code == 201, first.text
    first_id = first.json()["signature_id"]

    replay_same_op = client.post(f"/challenges/{chid}/signature", json=body)
    assert replay_same_op.status_code == 201
    assert replay_same_op.json()["signature_id"] == first_id

    second_op = dict(body, operation_id="sig-two")
    replay_new_op = client.post(f"/challenges/{chid}/signature", json=second_op)
    assert replay_new_op.status_code == 409
    assert replay_new_op.json()["error"]["code"] == "CHALLENGE_ALREADY_USED"

    detail = client.get(f"/agreements/{aid}").json()
    assert detail["signed_count"] == 1


def test_idempotent_create_same_content_and_conflicting_content(
    client: TestClient, wallet: Wallet
) -> None:
    payload = {
        "operation_id": "fixed-create-op",
        "initiator_account_id": "initiator",
        "title": "固定操作",
        "content_text": "相同正文",
        "seats": [{"seat_key": "alice", "original_account_id": "alice", "stage": 1}],
    }
    first = client.post("/agreements", json=payload)
    assert first.status_code == 201
    second = client.post("/agreements", json=payload)
    assert second.status_code == 201
    assert first.json()["agreement_id"] == second.json()["agreement_id"]

    changed = dict(payload, title="不同标题")
    conflict = client.post("/agreements", json=changed)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_REQUEST_CONFLICT"


def test_restart_preserves_state_and_idempotency(tmp_path: Path) -> None:
    db_path = tmp_path / "restart.db"

    # The wallet fixture depends on a client/app; create keys independently here.
    private_key = Ed25519PrivateKey.generate()
    public_b64 = b64e(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )

    app1 = create_app(db_path)
    with TestClient(app1) as client1:
        reg = client1.post(
            "/accounts",
            json={
                "operation_id": "restart-register",
                "account_id": "signer",
                "public_key_b64": public_b64,
            },
        )
        assert reg.status_code in (200, 201)
        created = client1.post(
            "/agreements",
            json={
                "operation_id": "restart-create",
                "initiator_account_id": "initiator",
                "title": "重启",
                "content_text": "重启后仍在\n",
                "seats": [{"seat_key": "only", "original_account_id": "signer", "stage": 1}],
            },
        )
        aid = created.json()["agreement_id"]
        client1.post(
            f"/agreements/{aid}/send",
            json={"operation_id": "restart-send", "initiator_account_id": "initiator"},
        )
        seat_id = created.json()["seats"][0]["seat_id"]
        # created response was draft and contains seat id; okay.
        challenge = client1.post(
            f"/agreements/{aid}/seats/{seat_id}/challenges",
            json={"operation_id": "restart-chal", "account_id": "signer"},
        )
        chid = challenge.headers["x-challenge-id"]
        sig = b64e(private_key.sign(challenge.content))
        signed = client1.post(
            f"/challenges/{chid}/signature",
            json={"operation_id": "restart-sig", "signature_b64": sig},
        )
        assert signed.status_code == 201, signed.text
        signature_id = signed.json()["signature_id"]

    app2 = create_app(db_path)
    with TestClient(app2) as client2:
        repeated_create = client2.post(
            "/agreements",
            json={
                "operation_id": "restart-create",
                "initiator_account_id": "initiator",
                "title": "重启",
                "content_text": "重启后仍在\n",
                "seats": [{"seat_key": "only", "original_account_id": "signer", "stage": 1}],
            },
        )
        assert repeated_create.status_code == 201
        assert repeated_create.json()["agreement_id"] == aid

        repeated_sign = client2.post(
            f"/challenges/{chid}/signature",
            json={"operation_id": "restart-sig", "signature_b64": sig},
        )
        assert repeated_sign.status_code == 201
        assert repeated_sign.json()["signature_id"] == signature_id

        replay_new_op = client2.post(
            f"/challenges/{chid}/signature",
            json={"operation_id": "after-restart-new-op", "signature_b64": sig},
        )
        assert replay_new_op.status_code == 409
        assert replay_new_op.json()["error"]["code"] == "CHALLENGE_ALREADY_USED"

        cert = client2.get(f"/agreements/{aid}/certificate")
        assert cert.status_code == 200
        report = verify_certificate(cert.json())
        assert report["valid"], report["errors"]
