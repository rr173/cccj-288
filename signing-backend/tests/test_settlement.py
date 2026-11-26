"""Automated tests for the receivable settlement extension.

Covers:
* receivable registration only under a completed signing agreement;
* largest-remainder proportional splits with tie-breaking;
* transfer applications, signing the generated transfer agreement through the
  existing challenge flow, shortfall termination and one-shot effectiveness;
* channel serial-number uniqueness and operation-id idempotency;
* partial refunds, original-line clawback order, pending deduction and the
  rule that future allocations absorb the debt first;
* disbursement limits;
* read models (holdings, allocation/reversal details, settlement accounts);
* restart durability and journal reconciliation;
* concurrent receipt/refund/transfer/disbursement serialization.
"""

from __future__ import annotations

import base64
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from signing_backend.db import connect
from signing_backend.errors import ApiError
from signing_backend.idempotency import OpResult, idempotent
from signing_backend.main import create_app
from signing_backend.schemas import (
    DisbursementRequest,
    ReceiptRegisterRequest,
    ReceivableRegisterRequest,
    RefundRegisterRequest,
    TransferApplyRequest,
    TransferConfirmRequest,
)
from signing_backend import settlement


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


ACCOUNTS = [
    "operator",
    "alice",
    "bob",
    "carol",
    "dave",
    "initiator",
]


class Wallet:
    def __init__(self) -> None:
        self.private_keys: dict[str, Ed25519PrivateKey] = {}
        self.public_keys: dict[str, str] = {}

    def add(self, account_id: str) -> None:
        private_key = Ed25519PrivateKey.generate()
        self.private_keys[account_id] = private_key
        self.public_keys[account_id] = b64e(
            private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def sign(self, account_id: str, raw: bytes) -> str:
        return b64e(self.private_keys[account_id].sign(raw))


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(tmp_path / "settlement.db")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def wallet(client: TestClient) -> Wallet:
    wallet = Wallet()
    for account_id in ACCOUNTS:
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


def complete_agreement(
    client: TestClient,
    wallet: Wallet,
    signers: list[str],
    *,
    initiator: str = "initiator",
    title: str = "基础债权协议",
    content_text: str = "应收款对应的基础协议正文\n",
    op: str | None = None,
) -> str:
    """Create, send and fully sign an agreement; return its agreement_id."""
    op = op or uuid.uuid4().hex
    seats = [
        {"seat_key": f"seat-{name}", "original_account_id": name, "stage": 1}
        for name in signers
    ]
    created = client.post(
        "/agreements",
        json={
            "operation_id": f"create-{op}",
            "initiator_account_id": initiator,
            "title": title,
            "content_text": content_text,
            "seats": seats,
        },
    )
    assert created.status_code == 201, created.text
    agreement = created.json()
    aid = agreement["agreement_id"]
    sent = client.post(
        f"/agreements/{aid}/send",
        json={"operation_id": f"send-{op}", "initiator_account_id": initiator},
    )
    assert sent.status_code == 200, sent.text
    for seat in sent.json()["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{aid}/seats/{seat['seat_id']}/challenges",
            json={"operation_id": f"chal-{op}-{account_id}", "account_id": account_id},
        )
        assert challenge.status_code == 201, challenge.text
        signature = wallet.sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={"operation_id": f"sign-{op}-{account_id}", "signature_b64": signature},
        )
        assert signed.status_code == 201, signed.text
    assert client.get(f"/agreements/{aid}").json()["status"] == "completed"
    return aid


def sign_transfer_agreement(
    client: TestClient, wallet: Wallet, transfer: dict[str, Any]
) -> None:
    """Sign both seats of a generated transfer agreement via existing flow."""
    detail = client.get(f"/agreements/{transfer['agreement_id']}").json()
    assert detail["status"] == "active"
    for seat in detail["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{detail['agreement_id']}/seats/{seat['seat_id']}/challenges",
            json={
                "operation_id": f"trf-chal-{transfer['transfer_id']}-{account_id}",
                "account_id": account_id,
            },
        )
        assert challenge.status_code == 201, challenge.text
        signature = wallet.sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={
                "operation_id": f"trf-sign-{transfer['transfer_id']}-{account_id}",
                "signature_b64": signature,
            },
        )
        assert signed.status_code == 201, signed.text
    assert client.get(f"/agreements/{detail['agreement_id']}").json()["status"] == "completed"


def register_receivable(
    client: TestClient,
    *,
    agreement_id: str,
    receivable_no: str,
    creditor: str = "alice",
    principal: int,
    op: str | None = None,
) -> dict[str, Any]:
    op = op or uuid.uuid4().hex
    response = client.post(
        "/receivables",
        json={
            "operation_id": op,
            "receivable_no": receivable_no,
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": "债务人-甲",
            "original_creditor_id": creditor,
            "principal_cents": principal,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_receivable_requires_completed_agreement(
    client: TestClient, wallet: Wallet
) -> None:
    op = uuid.uuid4().hex
    created = client.post(
        "/agreements",
        json={
            "operation_id": f"create-{op}",
            "initiator_account_id": "initiator",
            "title": "未完成协议",
            "content_text": "还没签完\n",
            "seats": [{"seat_key": "s", "original_account_id": "alice", "stage": 1}],
        },
    )
    aid = created.json()["agreement_id"]
    client.post(
        f"/agreements/{aid}/send",
        json={"operation_id": f"send-{op}", "initiator_account_id": "initiator"},
    )
    response = client.post(
        "/receivables",
        json={
            "operation_id": f"recv-{op}",
            "receivable_no": f"NO-{op}",
            "agreement_id": aid,
            "operator_account_id": "operator",
            "debtor": "d",
            "original_creditor_id": "alice",
            "principal_cents": 1000,
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "AGREEMENT_NOT_COMPLETED"


def test_register_receivable_and_query_holdings(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice"], op="base-1")
    receivable = register_receivable(
        client, agreement_id=aid, receivable_no="AR-001", principal=10000, op="recv-1"
    )
    rid = receivable["receivable_id"]
    assert receivable["remaining_cents"] == 10000
    assert receivable["status"] == "open"
    assert receivable["holdings"] == [
        {
            "holding_id": receivable["holdings"][0]["holding_id"],
            "account_id": "alice",
            "held_cents": 10000,
            "updated_at": receivable["holdings"][0]["updated_at"],
        }
    ]

    # Duplicate receivable number is rejected.
    dup = client.post(
        "/receivables",
        json={
            "operation_id": "recv-dup",
            "receivable_no": "AR-001",
            "agreement_id": aid,
            "operator_account_id": "operator",
            "debtor": "d",
            "original_creditor_id": "alice",
            "principal_cents": 1,
        },
    )
    assert dup.status_code == 409
    assert dup.json()["error"]["code"] == "RECEIVABLE_NO_CONFLICT"

    # Replaying the exact same operation returns the first result, no duplicate.
    replay = client.post(
        "/receivables",
        json={
            "operation_id": "recv-1",
            "receivable_no": "AR-001",
            "agreement_id": aid,
            "operator_account_id": "operator",
            "debtor": "债务人-甲",
            "original_creditor_id": "alice",
            "principal_cents": 10000,
        },
    )
    assert replay.status_code == 201
    assert replay.json()["receivable_id"] == rid

    listing = client.get("/receivables").json()
    assert any(item["receivable_id"] == rid for item in listing["receivables"])


# ---------------------------------------------------------------------------
# Proportional split
# ---------------------------------------------------------------------------


def test_receipt_split_largest_remainder_and_tie_break(
    client: TestClient, wallet: Wallet
) -> None:
    # Build holdings alice=50, bob=30, carol=20 via direct service calls is not
    # possible through HTTP, so derive them with transfers.
    aid = complete_agreement(client, wallet, ["alice", "bob", "carol"], op="split-base")
    receivable = register_receivable(
        client, agreement_id=aid, receivable_no="AR-SPLIT", principal=100, op="recv-split"
    )
    rid = receivable["receivable_id"]

    def transfer(transferor: str, transferee: str, amount: int, op: str) -> dict[str, Any]:
        applied = client.post(
            f"/receivables/{rid}/transfers",
            json={
                "operation_id": op,
                "transferor_account_id": transferor,
                "transferee_account_id": transferee,
                "amount_cents": amount,
            },
        )
        assert applied.status_code == 201, applied.text
        transfer_obj = applied.json()
        sign_transfer_agreement(client, wallet, transfer_obj)
        confirmed = client.post(
            f"/transfers/{transfer_obj['transfer_id']}/confirmation",
            json={"operation_id": f"confirm-{op}", "operator_account_id": "operator"},
        )
        assert confirmed.status_code == 200, confirmed.text
        return confirmed.json()

    # alice 100 -> bob 30, carol 20; alice keeps 50.
    transfer("alice", "bob", 30, "trf-bob")
    transfer("alice", "carol", 20, "trf-carol")
    holdings = {h["account_id"]: h["held_cents"] for h in client.get(f"/receivables/{rid}").json()["holdings"]}
    assert holdings == {"alice": 50, "bob": 30, "carol": 20}

    # Receipt of 10: exact proportions 5/3/2.
    receipt = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-10",
            "channel_serial_no": "CH-10",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    )
    assert receipt.status_code == 201, receipt.text
    alloc = {a["account_id"]: a["amount_cents"] for a in receipt.json()["allocations"]}
    assert alloc == {"alice": 5, "bob": 3, "carol": 2}

    # Receipt of 1 over weights 45/27/18 (sum 90): floor all zero, one leftover
    # cent goes to the largest remainder; alice's 45/90 is largest.
    receipt_one = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-1",
            "channel_serial_no": "CH-1",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    alloc_one = {a["account_id"]: a["amount_cents"] for a in receipt_one.json()["allocations"]}
    assert alloc_one == {"alice": 1}

    # Tie case: two equal holdings and 1 cent -> lower account id wins.
    rid2 = register_receivable(
        client, agreement_id=aid, receivable_no="AR-TIE", principal=10, op="recv-tie"
    )["receivable_id"]
    applied = client.post(
        f"/receivables/{rid2}/transfers",
        json={
            "operation_id": "trf-tie",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 5,
        },
    )
    sign_transfer_agreement(client, wallet, applied.json())
    client.post(
        f"/transfers/{applied.json()['transfer_id']}/confirmation",
        json={"operation_id": "confirm-tie", "operator_account_id": "operator"},
    )
    tie_receipt = client.post(
        f"/receivables/{rid2}/receipts",
        json={
            "operation_id": "rcpt-tie",
            "channel_serial_no": "CH-TIE",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    tie_alloc = [(a["account_id"], a["amount_cents"]) for a in tie_receipt.json()["allocations"]]
    assert tie_alloc == [("alice", 1)]  # alice < bob lexicographically


def test_receipt_cannot_exceed_remaining_and_serial_conflict(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice"], op="rcpt-limit")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-LIMIT", principal=100, op="recv-limit"
    )["receivable_id"]

    over = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-over",
            "channel_serial_no": "CH-OVER",
            "amount_cents": 101,
            "operator_account_id": "operator",
        },
    )
    assert over.status_code == 409
    assert over.json()["error"]["code"] == "RECEIPT_EXCEEDS_REMAINING"

    ok = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-full",
            "channel_serial_no": "CH-FULL",
            "amount_cents": 100,
            "operator_account_id": "operator",
        },
    )
    assert ok.status_code == 201
    assert client.get(f"/receivables/{rid}").json()["status"] == "settled"

    # Same serial number, different content -> rejected (not an idempotent replay).
    reused = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-reused-op",
            "channel_serial_no": "CH-FULL",
            "amount_cents": 5,
            "operator_account_id": "operator",
        },
    )
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "CHANNEL_SERIAL_CONFLICT"

    # Exact retry of the original request replays without double booking.
    retry = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-full",
            "channel_serial_no": "CH-FULL",
            "amount_cents": 100,
            "operator_account_id": "operator",
        },
    )
    assert retry.status_code == 201
    assert retry.json()["receipt_id"] == ok.json()["receipt_id"]
    account = client.get("/settlement-accounts/alice").json()
    assert account["available_cents"] == 100
    assert account["total_allocated_cents"] == 100


# ---------------------------------------------------------------------------
# Transfers
# ---------------------------------------------------------------------------


def test_transfer_lifecycle_unsigned_not_terminated_and_shortfall_terminates(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice", "bob"], op="trf-base")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-TRF", principal=1000, op="recv-trf"
    )["receivable_id"]

    applied = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-apply-1",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 400,
        },
    )
    assert applied.status_code == 201, applied.text
    transfer = applied.json()
    assert transfer["status"] == "pending"
    assert transfer["signed_count"] == 0

    # Confirming before all signatures is rejected but does NOT terminate.
    early = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "trf-early", "operator_account_id": "operator"},
    )
    assert early.status_code == 409
    assert early.json()["error"]["code"] == "TRANSFER_AGREEMENT_NOT_COMPLETED"
    assert client.get(f"/transfers/{transfer['transfer_id']}").json()["status"] == "pending"

    # Applying does not freeze principal: the debtor can still pay.
    receipt = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-during",
            "channel_serial_no": "CH-DURING",
            "amount_cents": 700,
            "operator_account_id": "operator",
        },
    )
    assert receipt.status_code == 201
    holdings = {h["account_id"]: h["held_cents"] for h in client.get(f"/receivables/{rid}").json()["holdings"]}
    assert holdings == {"alice": 300}

    # Now sign the transfer agreement fully and confirm: shortfall -> terminate.
    sign_transfer_agreement(client, wallet, transfer)
    confirm = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "trf-confirm-1", "operator_account_id": "operator"},
    )
    # The shortfall decision commits as a terminal state and is returned as 409.
    assert confirm.status_code == 409
    assert confirm.json()["error"]["code"] == "TRANSFER_INSUFFICIENT_PRINCIPAL"
    assert confirm.json()["status"] == "terminated"
    view = client.get(f"/transfers/{transfer['transfer_id']}").json()
    assert view["status"] == "terminated"
    assert view["terminated_reason"]

    # Replaying the same confirmation returns the stored terminal 409, not a
    # fresh TRANSFER_TERMINATED error.
    replay = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "trf-confirm-1", "operator_account_id": "operator"},
    )
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "TRANSFER_INSUFFICIENT_PRINCIPAL"
    assert replay.json()["status"] == "terminated"

    # Termination is permanent and never revives, even after a refund restores funds.
    refund = client.post(
        f"/receipts/{receipt.json()['receipt_id']}/refunds",
        json={
            "operation_id": "rfnd-revive",
            "channel_serial_no": "RF-REVIVE",
            "amount_cents": 700,
            "operator_account_id": "operator",
        },
    )
    assert refund.status_code == 201
    again = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "trf-confirm-retry", "operator_account_id": "operator"},
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "TRANSFER_TERMINATED"
    holdings = {h["account_id"]: h["held_cents"] for h in client.get(f"/receivables/{rid}").json()["holdings"]}
    assert holdings == {"alice": 1000}


def test_effective_transfer_moves_only_unrecovered_principal_once(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice", "bob", "carol"], op="eff-base")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-EFF", principal=1000, op="recv-eff"
    )["receivable_id"]

    # alice receives 300 first (already booked money must not move later).
    first = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-eff-1",
            "channel_serial_no": "CH-EFF-1",
            "amount_cents": 300,
            "operator_account_id": "operator",
        },
    )
    assert first.status_code == 201

    applied = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-eff",
            "transferor_account_id": "alice",
            "transferee_account_id": "carol",
            "amount_cents": 500,
        },
    )
    transfer = applied.json()
    sign_transfer_agreement(client, wallet, transfer)
    confirmed = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "confirm-eff", "operator_account_id": "operator"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "effective"

    holdings = {h["account_id"]: h["held_cents"] for h in client.get(f"/receivables/{rid}").json()["holdings"]}
    assert holdings == {"alice": 200, "carol": 500}

    # Second confirmation attempt is rejected: one application takes effect once.
    second = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "confirm-eff-again", "operator_account_id": "operator"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "TRANSFER_ALREADY_EFFECTIVE"

    # The earlier booked allocation stays with alice's settlement account.
    alice_account = client.get("/settlement-accounts/alice").json()
    assert alice_account["total_allocated_cents"] == 300
    carol_account = client.get("/settlement-accounts/carol").json()
    assert carol_account["total_allocated_cents"] == 0

    # Applying beyond current holding fails.
    too_big = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-too-big",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 201,
        },
    )
    assert too_big.status_code == 409
    assert too_big.json()["error"]["code"] == "TRANSFER_AMOUNT_EXCEEDS_HOLDING"

    # Self transfer rejected.
    self_resp = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-self",
            "transferor_account_id": "alice",
            "transferee_account_id": "alice",
            "amount_cents": 10,
        },
    )
    assert self_resp.status_code == 400
    assert self_resp.json()["error"]["code"] == "SELF_TRANSFER"


# ---------------------------------------------------------------------------
# Refunds, clawback and pending deduction
# ---------------------------------------------------------------------------


def test_partial_refunds_reverse_original_lines_and_restore_principal(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice", "bob"], op="rfnd-base")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-RFND", principal=100, op="recv-rfnd"
    )["receivable_id"]
    # Split holdings 60/40.
    applied = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-rfnd",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 40,
        },
    )
    sign_transfer_agreement(client, wallet, applied.json())
    client.post(
        f"/transfers/{applied.json()['transfer_id']}/confirmation",
        json={"operation_id": "confirm-rfnd", "operator_account_id": "operator"},
    )

    # Receipt 10 -> alice 6, bob 4.
    receipt = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-rfnd",
            "channel_serial_no": "CH-RFND",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    ).json()
    receipt_id = receipt["receipt_id"]
    assert {a["account_id"]: a["amount_cents"] for a in receipt["allocations"]} == {
        "alice": 6,
        "bob": 4,
    }

    # Move bob's remaining principal to carol BEFORE the refund: the refund
    # must still return to bob (original payee), not recompute by current ratio.
    applied2 = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-rfnd-2",
            "transferor_account_id": "bob",
            "transferee_account_id": "carol",
            "amount_cents": 36,
        },
    )
    sign_transfer_agreement(client, wallet, applied2.json())
    client.post(
        f"/transfers/{applied2.json()['transfer_id']}/confirmation",
        json={"operation_id": "confirm-rfnd-2", "operator_account_id": "operator"},
    )

    # Refund part 1: 7 cents.  Original lines sorted 6(alice) then 4(bob):
    # take 6 from alice, 1 from bob.
    refund1 = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": "rfnd-1",
            "channel_serial_no": "RF-1",
            "amount_cents": 7,
            "operator_account_id": "operator",
        },
    )
    assert refund1.status_code == 201, refund1.text
    reversals = [(r["account_id"], r["amount_cents"]) for r in refund1.json()["reversals"]]
    assert reversals == [("alice", 6), ("bob", 1)]

    # Refund part 2: remaining 3, all from bob's line.
    refund2 = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": "rfnd-2",
            "channel_serial_no": "RF-2",
            "amount_cents": 3,
            "operator_account_id": "operator",
        },
    )
    assert refund2.status_code == 201
    reversals2 = [(r["account_id"], r["amount_cents"]) for r in refund2.json()["reversals"]]
    assert reversals2 == [("bob", 3)]

    # Cumulative cap enforced.
    over = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": "rfnd-over",
            "channel_serial_no": "RF-OVER",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    assert over.status_code == 409
    assert over.json()["error"]["code"] == "REFUND_EXCEEDS_RECEIPT"

    # Refund serial reuse with different content rejected.
    reused = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": "rfnd-reuse-op",
            "channel_serial_no": "RF-1",
            "amount_cents": 2,
            "operator_account_id": "operator",
        },
    )
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "CHANNEL_SERIAL_CONFLICT"

    # Principal restored to the original payees; receivable open again.
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["remaining_cents"] == 100
    holdings = {h["account_id"]: h["held_cents"] for h in detail["holdings"]}
    assert holdings == {"alice": 60, "bob": 4, "carol": 36}

    receipt_view = client.get(f"/receipts/{receipt_id}").json()
    assert receipt_view["refunded_cents"] == 10
    assert receipt_view["remaining_cents"] == 0
    assert all(a["unreversed_cents"] == 0 for a in receipt_view["allocations"])


def test_clawback_debt_offsets_future_allocations_and_disbursement_limits(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice", "bob"], op="claw-base")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-CLAW", principal=100, op="recv-claw"
    )["receivable_id"]

    # alice gets 10, draws 8 out -> available 2.
    client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-claw",
            "channel_serial_no": "CH-CLAW",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    )
    disb = client.post(
        "/disbursements",
        json={
            "operation_id": "dsb-1",
            "account_id": "alice",
            "amount_cents": 8,
            "operator_account_id": "operator",
            "note": "first payout",
        },
    )
    assert disb.status_code == 201
    assert client.get("/settlement-accounts/alice").json()["available_cents"] == 2

    # Refund the full 10: claw 2 from balance, 8 becomes pending deduction.
    receipt_id = client.get(f"/receivables/{rid}").json()["receipt_ids"][0]
    refund = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": "rfnd-claw",
            "channel_serial_no": "RF-CLAW",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    )
    assert refund.status_code == 201
    reversal = refund.json()["reversals"][0]
    assert reversal["clawback_from_balance_cents"] == 2
    assert reversal["clawback_to_deduction_cents"] == 8

    alice = client.get("/settlement-accounts/alice").json()
    assert alice["available_cents"] == 0
    assert alice["pending_deduction_cents"] == 8
    # The historical disbursement record is untouched.
    assert alice["disbursements"][0]["amount_cents"] == 8
    assert alice["total_disbursed_cents"] == 8

    # Over-draw is rejected.
    bad_disb = client.post(
        "/disbursements",
        json={
            "operation_id": "dsb-bad",
            "account_id": "alice",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    assert bad_disb.status_code == 409
    assert bad_disb.json()["error"]["code"] == "INSUFFICIENT_AVAILABLE_BALANCE"

    # A new 10-cent allocation first absorbs the 8 debt; net credit is 2.
    new_receipt = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-claw-2",
            "channel_serial_no": "CH-CLAW-2",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    )
    assert new_receipt.status_code == 201
    allocation = new_receipt.json()["allocations"][0]
    assert allocation["amount_cents"] == 10
    assert allocation["deduction_offset_cents"] == 8
    assert allocation["net_credited_cents"] == 2
    alice = client.get("/settlement-accounts/alice").json()
    assert alice["available_cents"] == 2
    assert alice["pending_deduction_cents"] == 0
    assert alice["total_allocated_cents"] == 20

    # Disbursement idempotency: same request replays, no double withdrawal.
    payload = {
        "operation_id": "dsb-2",
        "account_id": "alice",
        "amount_cents": 2,
        "operator_account_id": "operator",
    }
    first = client.post("/disbursements", json=payload)
    replay = client.post("/disbursements", json=payload)
    assert first.status_code == 201 and replay.status_code == 201
    assert first.json()["disbursement_id"] == replay.json()["disbursement_id"]
    assert client.get("/settlement-accounts/alice").json()["available_cents"] == 0


# ---------------------------------------------------------------------------
# Restart durability and journal reconciliation
# ---------------------------------------------------------------------------


def test_restart_preserves_settlement_state_and_ledger_reconciles(tmp_path: Path) -> None:
    db_path = tmp_path / "restart-settlement.db"
    wallet = Wallet()
    wallet.add("alice")
    wallet.add("initiator")
    wallet.add("operator")

    app1 = create_app(db_path)
    with TestClient(app1) as client1:
        client1.post(
            "/accounts",
            json={
                "operation_id": "reg-alice",
                "account_id": "alice",
                "public_key_b64": wallet.public_keys["alice"],
            },
        )
        client1.post(
            "/accounts",
            json={
                "operation_id": "reg-initiator",
                "account_id": "initiator",
                "public_key_b64": wallet.public_keys["initiator"],
            },
        )
        client1.post(
            "/accounts",
            json={
                "operation_id": "reg-operator",
                "account_id": "operator",
                "public_key_b64": wallet.public_keys["operator"],
            },
        )
        aid = complete_agreement(client1, wallet, ["alice"], op="restart-base")
        rid = register_receivable(
            client1, agreement_id=aid, receivable_no="AR-RESTART", principal=50, op="recv-restart"
        )["receivable_id"]
        receipt = client1.post(
            f"/receivables/{rid}/receipts",
            json={
                "operation_id": "rcpt-restart",
                "channel_serial_no": "CH-RESTART",
                "amount_cents": 20,
                "operator_account_id": "operator",
            },
        ).json()
        client1.post(
            "/disbursements",
            json={
                "operation_id": "dsb-restart",
                "account_id": "alice",
                "amount_cents": 5,
                "operator_account_id": "operator",
            },
        )
        client1.post(
            f"/receipts/{receipt['receipt_id']}/refunds",
            json={
                "operation_id": "rfnd-restart",
                "channel_serial_no": "RF-RESTART",
                "amount_cents": 7,
                "operator_account_id": "operator",
            },
        )

    app2 = create_app(db_path)
    with TestClient(app2) as client2:
        detail = client2.get(f"/receivables/{rid}").json()
        # 50 - 20 + 7 = 37 remaining.
        assert detail["remaining_cents"] == 37
        assert detail["holdings"][0]["held_cents"] == 37

        account = client2.get("/settlement-accounts/alice").json()
        # 20 allocated - 5 disbursed - 7 clawed back = 8 available.
        assert account["available_cents"] == 8
        assert account["total_allocated_cents"] == 20
        assert account["total_clawback_cents"] == 7
        assert account["total_disbursed_cents"] == 5
        assert len(account["disbursements"]) == 1

        # Replaying an idempotent operation after restart returns stored result.
        replay = client2.post(
            f"/receivables/{rid}/receipts",
            json={
                "operation_id": "rcpt-restart",
                "channel_serial_no": "CH-RESTART",
                "amount_cents": 20,
                "operator_account_id": "operator",
            },
        )
        assert replay.status_code == 201
        assert replay.json()["receipt_id"] == receipt["receipt_id"]
        assert client2.get("/settlement-accounts/alice").json()["available_cents"] == 8

    # Reconcile balances purely from the append-only ledger.
    conn = connect(db_path)
    try:
        rows = conn.execute(
            "SELECT delta_available, delta_deduction FROM settlement_ledger WHERE account_id = 'alice'"
        ).fetchall()
        assert sum(r["delta_available"] for r in rows) == 8
        assert sum(r["delta_deduction"] for r in rows) == 0
        # Receivable principal conservation.
        recv = conn.execute("SELECT * FROM receivables WHERE receivable_id = ?", (rid,)).fetchone()
        holding_total = conn.execute(
            "SELECT COALESCE(SUM(held_cents), 0) AS t FROM receivable_holdings WHERE receivable_id = ?",
            (rid,),
        ).fetchone()["t"]
        assert recv["remaining_cents"] == holding_total
        # Allocation totals equal gross receipt amounts.
        alloc_total = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS t FROM receipt_allocations"
        ).fetchone()["t"]
        receipt_total = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS t FROM receipts"
        ).fetchone()["t"]
        assert alloc_total == receipt_total
        reversal_total = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS t FROM refund_reversals"
        ).fetchone()["t"]
        refund_total = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS t FROM refunds"
        ).fetchone()["t"]
        assert reversal_total == refund_total
    finally:
        conn.close()


def test_refund_equal_amount_lines_break_tie_by_account(
    client: TestClient, wallet: Wallet
) -> None:
    aid = complete_agreement(client, wallet, ["alice", "bob"], op="tie-rfnd")
    rid = register_receivable(
        client, agreement_id=aid, receivable_no="AR-TIE-RFND", principal=100, op="recv-tie-rf"
    )["receivable_id"]
    # 50/50 holdings.
    applied = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-tie-rfnd",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 50,
        },
    )
    sign_transfer_agreement(client, wallet, applied.json())
    client.post(
        f"/transfers/{applied.json()['transfer_id']}/confirmation",
        json={"operation_id": "confirm-tie-rfnd", "operator_account_id": "operator"},
    )
    # A 10-cent receipt splits into two equal 5-cent lines (alice, bob).
    receipt = client.post(
        f"/receivables/{rid}/receipts",
        json={
            "operation_id": "rcpt-tie-rfnd",
            "channel_serial_no": "CH-TIE-RFND",
            "amount_cents": 10,
            "operator_account_id": "operator",
        },
    ).json()
    lines = {a["account_id"]: a["amount_cents"] for a in receipt["allocations"]}
    assert lines == {"alice": 5, "bob": 5}

    # Refund one cent: equal amounts -> lower account id (alice) is reversed first.
    refund = client.post(
        f"/receipts/{receipt['receipt_id']}/refunds",
        json={
            "operation_id": "rfnd-tie",
            "channel_serial_no": "RF-TIE",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    assert refund.status_code == 201
    assert [(r["account_id"], r["amount_cents"]) for r in refund.json()["reversals"]] == [
        ("alice", 1)
    ]


def test_terminated_transfer_persists_across_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "terminated.db"
    wallet = Wallet()
    for name in ["alice", "bob", "operator", "initiator"]:
        wallet.add(name)
    app1 = create_app(db_path)
    transfer_id = None
    with TestClient(app1) as client1:
        for name in ["alice", "bob", "operator", "initiator"]:
            client1.post(
                "/accounts",
                json={
                    "operation_id": f"reg-{name}",
                    "account_id": name,
                    "public_key_b64": wallet.public_keys[name],
                },
            )
        aid = complete_agreement(client1, wallet, ["alice"], op="term-base")
        rid = register_receivable(
            client1, agreement_id=aid, receivable_no="AR-TERM", principal=100, op="recv-term"
        )["receivable_id"]
        applied = client1.post(
            f"/receivables/{rid}/transfers",
            json={
                "operation_id": "trf-term",
                "transferor_account_id": "alice",
                "transferee_account_id": "bob",
                "amount_cents": 80,
            },
        ).json()
        transfer_id = applied["transfer_id"]
        sign_transfer_agreement(client1, wallet, applied)
        # Debtor pays 50 while the application is pending; alice keeps 50 < 80.
        client1.post(
            f"/receivables/{rid}/receipts",
            json={
                "operation_id": "rcpt-term",
                "channel_serial_no": "CH-TERM",
                "amount_cents": 50,
                "operator_account_id": "operator",
            },
        )
        confirm = client1.post(
            f"/transfers/{transfer_id}/confirmation",
            json={"operation_id": "confirm-term", "operator_account_id": "operator"},
        )
        assert confirm.status_code == 409
        assert confirm.json()["status"] == "terminated"

    app2 = create_app(db_path)
    with TestClient(app2) as client2:
        view = client2.get(f"/transfers/{transfer_id}").json()
        assert view["status"] == "terminated"
        # Replaying the stored confirmation after restart returns the same 409.
        replay = client2.post(
            f"/transfers/{transfer_id}/confirmation",
            json={"operation_id": "confirm-term", "operator_account_id": "operator"},
        )
        assert replay.status_code == 409
        assert replay.json()["status"] == "terminated"
        # The transfer list filter by receivable still reports it.
        listing = client2.get(f"/transfers?receivable_id={view['receivable_id']}").json()
        assert any(t["transfer_id"] == transfer_id and t["status"] == "terminated"
                   for t in listing["transfers"])


# ---------------------------------------------------------------------------
# Pure split unit tests
# ---------------------------------------------------------------------------


def test_largest_remainder_split_exhausts_amount() -> None:
    holders = [("a", 333), ("b", 333), ("c", 334)]
    for total in range(1, 1001):
        shares = dict(settlement.largest_remainder_split(holders, total))
        assert sum(shares.values()) == total
        assert all(value >= 0 for value in shares.values())

    # Classic remainder case: 10 over 3 equal weights -> 4,3,3 with the extra
    # cent going to the lexicographically smallest account on equal remainders.
    shares = settlement.largest_remainder_split([("a", 1), ("b", 1), ("c", 1)], 10)
    assert shares == [("a", 4), ("b", 3), ("c", 3)]

    shares = settlement.largest_remainder_split([("a", 1), ("b", 1)], 1)
    assert shares == [("a", 1), ("b", 0)]


# ---------------------------------------------------------------------------
# Concurrency: writers must be equivalent to some serial order
# ---------------------------------------------------------------------------


def test_concurrent_writers_are_serializable_and_atomic(tmp_path: Path) -> None:
    db_path = tmp_path / "concurrent.db"
    app = create_app(db_path)
    wallet = Wallet()
    for name in ["alice", "bob", "operator"]:
        wallet.add(name)
    with TestClient(app) as client:
        for name in ["alice", "bob", "operator"]:
            client.post(
                "/accounts",
                json={
                    "operation_id": f"reg-{name}",
                    "account_id": name,
                    "public_key_b64": wallet.public_keys[name],
                },
            )
        aid = complete_agreement(client, wallet, ["alice"], op="conc-base")
        rid = register_receivable(
            client, agreement_id=aid, receivable_no="AR-CONC", principal=1000, op="recv-conc"
        )["receivable_id"]
    barrier = threading.Barrier(4)
    run = uuid.uuid4().hex

    def receipt_worker(serial: str, amount: int) -> tuple[str, Any]:
        barrier.wait(timeout=30)
        conn = connect(db_path)
        try:
            data = ReceiptRegisterRequest(
                operation_id=f"rcpt-{serial}-{run}",
                channel_serial_no=serial,
                amount_cents=amount,
                operator_account_id="operator",
            )
            idempotent(
                conn,
                "receipt.register",
                data.operation_id,
                {"receivable_id": rid, "body": data.model_dump()},
                lambda c: OpResult(201, settlement.register_receipt_tx(c, rid, data)),
            )
            return "ok", serial
        except Exception as exc:  # noqa: BLE001
            return "error", getattr(exc, "code", exc.__class__.__name__)
        finally:
            conn.close()

    def disbursement_worker() -> tuple[str, Any]:
        barrier.wait(timeout=30)
        # Retry briefly: under a random serial order this worker may reach the
        # database before either receipt has credited alice's account.
        for attempt in range(50):
            conn = connect(db_path)
            try:
                data = DisbursementRequest(
                    operation_id=f"dsb-{run}",
                    account_id="alice",
                    amount_cents=100,
                    operator_account_id="operator",
                )
                idempotent(
                    conn,
                    "disbursement.register",
                    data.operation_id,
                    {"body": data.model_dump()},
                    lambda c: OpResult(201, settlement.register_disbursement_tx(c, data)),
                )
                return "ok", "disb"
            except ApiError as exc:
                if exc.code != "INSUFFICIENT_AVAILABLE_BALANCE":
                    return "error", exc.code
                time.sleep(0.05)
            finally:
                conn.close()
        return "error", "INSUFFICIENT_AVAILABLE_BALANCE"

    # Prepare a fully-signed 250-cent transfer to bob before the race so that
    # only the confirmation decision collides with receipts/disbursement.
    prep_conn = connect(db_path)
    try:
        apply_data = TransferApplyRequest(
            operation_id=f"trf-apply-{run}",
            transferor_account_id="alice",
            transferee_account_id="bob",
            amount_cents=250,
        )
        applied = idempotent(
            prep_conn,
            "transfer.apply",
            apply_data.operation_id,
            {"receivable_id": rid, "body": apply_data.model_dump()},
            lambda c: OpResult(201, settlement.apply_transfer_tx(c, rid, apply_data)),
        )
        transfer_id = applied.body["transfer_id"]
        agreement_id = applied.body["agreement_id"]
    finally:
        prep_conn.close()

    with TestClient(app) as signing_client:
        detail = signing_client.get(f"/agreements/{agreement_id}").json()
        for seat in detail["seats"]:
            account_id = seat["original_account_id"]
            challenge = signing_client.post(
                f"/agreements/{agreement_id}/seats/{seat['seat_id']}/challenges",
                json={
                    "operation_id": f"trf-chal-{run}-{account_id}",
                    "account_id": account_id,
                },
            )
            signature = wallet.sign(account_id, challenge.content)
            signing_client.post(
                f"/challenges/{challenge.headers['x-challenge-id']}/signature",
                json={
                    "operation_id": f"trf-sign-{run}-{account_id}",
                    "signature_b64": signature,
                },
            )

    def transfer_worker() -> tuple[str, Any]:
        barrier.wait(timeout=30)
        conn = connect(db_path)
        try:
            data = TransferConfirmRequest(
                operation_id=f"trf-confirm-{run}",
                operator_account_id="operator",
            )
            idempotent(
                conn,
                "transfer.confirm",
                data.operation_id,
                {"transfer_id": transfer_id, "body": data.model_dump()},
                lambda c: settlement.confirm_transfer_tx(c, transfer_id, data),
            )
            return "ok", "transfer"
        except Exception as exc:  # noqa: BLE001
            return "error", getattr(exc, "code", exc.__class__.__name__)
        finally:
            conn.close()

    # Two receipts (400 + 350 = 750), one 100 disbursement, one 250 transfer.
    # Any serial order is acceptable: a disbursement that serializes before
    # the receipts legitimately fails for insufficient balance, and a
    # confirmed transfer may be followed by further receipts that reduce the
    # transferee holding.  The assertions below check cross-cutting
    # invariants that must hold for every possible serial order.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(receipt_worker, "CH-C1", 400),
            pool.submit(receipt_worker, "CH-C2", 350),
            pool.submit(disbursement_worker),
            pool.submit(transfer_worker),
        ]
        outcomes = [f.result(timeout=40) for f in futures]

    conn = connect(db_path)
    try:
        recv = conn.execute("SELECT * FROM receivables WHERE receivable_id = ?", (rid,)).fetchone()
        holding_total = conn.execute(
            "SELECT COALESCE(SUM(held_cents), 0) AS t FROM receivable_holdings WHERE receivable_id = ?",
            (rid,),
        ).fetchone()["t"]
        # Invariant 1: remaining principal equals sum of holdings.
        assert recv["remaining_cents"] == holding_total
        # Invariant 2: remaining + recovered(net of refunds) == principal.
        recovered = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS t FROM receipts WHERE receivable_id = ?",
            (rid,),
        ).fetchone()["t"]
        refunded = conn.execute(
            """
            SELECT COALESCE(SUM(rf.amount_cents),0) AS t
            FROM refunds rf JOIN receipts r ON r.receipt_id = rf.receipt_id
            WHERE r.receivable_id = ?
            """,
            (rid,),
        ).fetchone()["t"]
        assert recv["remaining_cents"] + recovered - refunded == 1000

        # Both receipts are distinct serials; both must have booked exactly once.
        serials = {
            row["channel_serial_no"]
            for row in conn.execute("SELECT channel_serial_no FROM receipts").fetchall()
        }
        assert serials == {"CH-C1", "CH-C2"}

        # Settlement money conservation across accounts.
        money = conn.execute(
            """
            SELECT COALESCE(SUM(available_cents),0) AS avail,
                   COALESCE(SUM(pending_deduction_cents),0) AS debt,
                   COALESCE(SUM(total_disbursed_cents),0) AS disb
            FROM settlement_accounts
            """
        ).fetchone()
        # No refunds here, so available + disbursed equals gross allocated 750.
        assert money["avail"] + money["disb"] == 750
        assert money["debt"] == 0

        # The transfer reaches exactly one terminal decision.  If it took
        # effect, bob's current holding must equal the transferred 250 minus
        # whatever share of later receipts was allocated to him, plus any
        # later refunds restoring those lines: the system must be explainable
        # by one concrete serial order.
        transfer = conn.execute(
            "SELECT * FROM transfer_applications WHERE receivable_id = ?", (rid,)
        ).fetchone()
        assert transfer["status"] in {"effective", "terminated"}
        if transfer["status"] == "effective":
            bob_holding = conn.execute(
                "SELECT held_cents FROM receivable_holdings WHERE receivable_id = ? AND account_id = 'bob'",
                (rid,),
            ).fetchone()["held_cents"]
            bob_allocated_after = conn.execute(
                """
                SELECT COALESCE(SUM(a.amount_cents), 0) AS t
                FROM receipt_allocations a
                JOIN receipts r ON r.receipt_id = a.receipt_id
                WHERE r.receivable_id = ? AND a.account_id = 'bob'
                  AND r.created_at >= ?
                """,
                (rid, transfer["effective_at"]),
            ).fetchone()["t"]
            bob_reversed_after = conn.execute(
                """
                SELECT COALESCE(SUM(rv.amount_cents), 0) AS t
                FROM refund_reversals rv
                JOIN refunds rf ON rf.refund_id = rv.refund_id
                JOIN receipts r ON r.receipt_id = rf.receipt_id
                WHERE r.receivable_id = ? AND rv.account_id = 'bob'
                  AND rf.created_at >= ?
                """,
                (rid, transfer["effective_at"]),
            ).fetchone()["t"]
            assert bob_holding == 250 - bob_allocated_after + bob_reversed_after
            assert bob_holding >= 0
    finally:
        conn.close()

    # Every worker reaches a known terminal outcome; no partial writes.  The
    # disbursement retries until the receipts have funded the account, so all
    # four operations succeed in some serial order.
    assert all(status == "ok" for status, _detail in outcomes), outcomes


def test_concurrent_identical_receipt_retry_books_once(tmp_path: Path) -> None:
    db_path = tmp_path / "retry-once.db"
    app = create_app(db_path)
    wallet = Wallet()
    wallet.add("alice")
    wallet.add("operator")
    with TestClient(app) as client:
        for name in ["alice", "operator"]:
            client.post(
                "/accounts",
                json={
                    "operation_id": f"reg-{name}",
                    "account_id": name,
                    "public_key_b64": wallet.public_keys[name],
                },
            )
        aid = complete_agreement(client, wallet, ["alice"], op="once-base")
        rid = register_receivable(
            client, agreement_id=aid, receivable_no="AR-ONCE", principal=100, op="recv-once"
        )["receivable_id"]

    barrier = threading.Barrier(5)

    def worker() -> str:
        barrier.wait(timeout=30)
        conn = connect(db_path)
        try:
            data = ReceiptRegisterRequest(
                operation_id="same-op-id",
                channel_serial_no="CH-SAME",
                amount_cents=40,
                operator_account_id="operator",
            )
            idempotent(
                conn,
                "receipt.register",
                data.operation_id,
                {"receivable_id": rid, "body": data.model_dump()},
                lambda c: OpResult(201, settlement.register_receipt_tx(c, rid, data)),
            )
            return "ok"
        except Exception as exc:  # noqa: BLE001
            return f"{getattr(exc, 'code', exc.__class__.__name__)}: {exc}"
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=5) as pool:
        # Submit every worker before blocking on any result, otherwise the
        # first worker would wait at the barrier for parties that were never
        # scheduled (a sequential submit/result loop deadlocks).
        futures = [pool.submit(worker) for _ in range(5)]
        outcomes = [future.result(timeout=40) for future in futures]

    assert all(code == "ok" for code in outcomes), outcomes
    conn = connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) AS n FROM receipts").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM receipt_allocations").fetchone()["n"] == 1
        account = conn.execute(
            "SELECT * FROM settlement_accounts WHERE account_id = 'alice'"
        ).fetchone()
        assert account["available_cents"] == 40
        assert account["total_allocated_cents"] == 40
    finally:
        conn.close()
