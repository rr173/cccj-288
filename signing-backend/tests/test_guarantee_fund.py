"""Automated tests for guarantee-fund compensation and subrogation."""

from __future__ import annotations

import base64
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from signing_backend.db import connect, init_db
from signing_backend.idempotency import OpResult, idempotent
from signing_backend.main import create_app
from signing_backend.schemas import CompensationCreateRequest
from signing_backend import settlement


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


ACCOUNTS = ["operator", "alice", "bob", "carol", "initiator"]


class Wallet:
    def __init__(self) -> None:
        self.keys: dict[str, Ed25519PrivateKey] = {}
        self.public_keys: dict[str, str] = {}

    def add(self, account_id: str) -> None:
        key = Ed25519PrivateKey.generate()
        self.keys[account_id] = key
        self.public_keys[account_id] = b64e(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def sign(self, account_id: str, body: bytes) -> str:
        return b64e(self.keys[account_id].sign(body))


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(tmp_path / "guarantee.db")
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
                "operation_id": f"account-{account_id}",
                "account_id": account_id,
                "public_key_b64": wallet.public_keys[account_id],
                "display_name": account_id,
            },
        )
        assert response.status_code in (200, 201), response.text
    return wallet


def completed_agreement(
    client: TestClient, wallet: Wallet, signers: list[str], *, op: str
) -> str:
    created = client.post(
        "/agreements",
        json={
            "operation_id": f"agr-{op}",
            "initiator_account_id": "initiator",
            "title": f"基础协议-{op}",
            "content_text": "simulated underlying receivable agreement\n",
            "seats": [
                {"seat_key": f"seat-{name}", "original_account_id": name, "stage": 1}
                for name in signers
            ],
        },
    )
    assert created.status_code == 201, created.text
    agreement_id = created.json()["agreement_id"]
    sent = client.post(
        f"/agreements/{agreement_id}/send",
        json={"operation_id": f"send-{op}", "initiator_account_id": "initiator"},
    )
    assert sent.status_code == 200, sent.text
    for seat in sent.json()["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{agreement_id}/seats/{seat['seat_id']}/challenges",
            json={"operation_id": f"challenge-{op}-{account_id}", "account_id": account_id},
        )
        assert challenge.status_code == 201, challenge.text
        signature = wallet.sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={
                "operation_id": f"sign-{op}-{account_id}",
                "signature_b64": signature,
            },
        )
        assert signed.status_code == 201, signed.text
    return agreement_id


def make_receivable(
    client: TestClient,
    wallet: Wallet,
    *,
    op: str,
    creditor: str = "alice",
    principal: int = 100,
    signers: list[str] | None = None,
) -> str:
    agreement_id = completed_agreement(
        client, wallet, signers or [creditor], op=f"base-{op}"
    )
    response = client.post(
        "/receivables",
        json={
            "operation_id": f"recv-{op}",
            "receivable_no": f"AR-{op}",
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": "模拟债务人",
            "original_creditor_id": creditor,
            "principal_cents": principal,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["receivable_id"]


def create_fund(
    client: TestClient, *, op: str, amount: int = 1000, fund_id: str | None = None
) -> str:
    response = client.post(
        "/guarantee-funds",
        json={
            "operation_id": f"fund-{op}",
            "fund_id": fund_id or f"fund-{op}",
            "name": f"担保基金 {op}",
            "operator_account_id": "operator",
        },
    )
    assert response.status_code == 201, response.text
    fund_id = response.json()["fund_id"]
    if amount:
        contribution = client.post(
            f"/guarantee-funds/{fund_id}/contributions",
            json={
                "operation_id": f"contrib-{op}",
                "amount_cents": amount,
                "operator_account_id": "operator",
            },
        )
        assert contribution.status_code == 201, contribution.text
    return fund_id


def bind(
    client: TestClient, receivable_id: str, fund_id: str, *, op: str, limit: int = 100
) -> dict[str, Any]:
    response = client.post(
        f"/receivables/{receivable_id}/guarantee-binding",
        json={
            "operation_id": f"bind-{op}",
            "fund_id": fund_id,
            "limit_cents": limit,
            "operator_account_id": "operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def compensate(
    client: TestClient,
    receivable_id: str,
    *,
    op: str,
    creditor: str = "alice",
    amount: int,
    expected_status: int = 201,
) -> Any:
    response = client.post(
        f"/receivables/{receivable_id}/compensations",
        json={
            "operation_id": f"comp-{op}",
            "creditor_account_id": creditor,
            "amount_cents": amount,
            "operator_account_id": "operator",
        },
    )
    assert response.status_code == expected_status, response.text
    return response.json()


def receipt(
    client: TestClient, receivable_id: str, *, serial: str, amount: int
) -> dict[str, Any]:
    response = client.post(
        f"/receivables/{receivable_id}/receipts",
        json={
            "operation_id": f"op-{serial}",
            "channel_serial_no": serial,
            "amount_cents": amount,
            "operator_account_id": "operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def refund(
    client: TestClient, receipt_id: str, *, serial: str, amount: int
) -> dict[str, Any]:
    response = client.post(
        f"/receipts/{receipt_id}/refunds",
        json={
            "operation_id": f"op-{serial}",
            "channel_serial_no": serial,
            "amount_cents": amount,
            "operator_account_id": "operator",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_compensation_converts_ordinary_principal_and_recovers_fund(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="core")
    fund_id = create_fund(client, op="core", amount=1000)
    bind(client, rid, fund_id, op="core", limit=60)

    comp = compensate(client, rid, op="core", amount=30)
    assert comp["outstanding_cents"] == 30
    assert comp["net_credited_cents"] == 30

    detail = client.get(f"/receivables/{rid}").json()
    assert detail["principal_cents"] == 100
    assert detail["remaining_cents"] == 100  # compensation is not debtor payment
    assert detail["ordinary_remaining_cents"] == 70
    assert detail["guarantee_outstanding_cents"] == 30
    assert detail["holdings"][0]["held_cents"] == 70

    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["available_cents"] == 970
    assert fund["gap_cents"] == 0
    alice = client.get("/settlement-accounts/alice").json()
    assert alice["available_cents"] == 30

    paid = receipt(client, rid, serial="CH-CORE-1", amount=30)
    assert [a["compensation_id"] for a in paid["guarantee_allocations"]] == [
        comp["compensation_id"]
    ]
    assert paid["allocations"] == []
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["available_cents"] == 1000
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["remaining_cents"] == 70
    assert detail["guarantee_outstanding_cents"] == 0

    # Recovered limit can support a new batch.
    second = compensate(client, rid, op="core-2", amount=60)
    assert second["outstanding_cents"] == 60
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["ordinary_remaining_cents"] == 10
    assert detail["guarantee_outstanding_cents"] == 60
    binding = detail["guarantee_binding"]
    assert binding["remaining_limit_cents"] == 0


def test_refund_ordinary_first_then_guarantee_batches_reverse_order(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="order")
    fund_id = create_fund(client, op="order", amount=1000)
    bind(client, rid, fund_id, op="order", limit=100)

    c1 = compensate(client, rid, op="order-1", amount=20)
    c2 = compensate(client, rid, op="order-2", amount=30)

    paid = receipt(client, rid, serial="CH-ORDER", amount=80)
    assert [a["compensation_id"] for a in paid["guarantee_allocations"]] == [
        c1["compensation_id"],
        c2["compensation_id"],
    ]
    assert [(a["account_id"], a["amount_cents"]) for a in paid["allocations"]] == [
        ("alice", 30)
    ]

    back = refund(client, paid["receipt_id"], serial="RF-ORDER-1", amount=70)
    assert [(r["kind"], r.get("account_id"), r.get("compensation_id"), r["amount_cents"]) for r in back["all_reversals"]] == [
        ("ordinary", "alice", None, 30),
        ("guarantee", None, c2["compensation_id"], 30),
        ("guarantee", None, c1["compensation_id"], 10),
    ]

    batches = {
        b["compensation_id"]: b["outstanding_cents"]
        for b in client.get(f"/receivables/{rid}").json()["compensation_batches"]
    }
    assert batches[c1["compensation_id"]] == 10
    assert batches[c2["compensation_id"]] == 30
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    # Only the 40 guarantee slice touches the fund; 30 ordinary is clawed
    # back from Alice's settlement account.
    assert fund["available_cents"] == 960
    assert fund["gap_cents"] == 0

    back2 = refund(client, paid["receipt_id"], serial="RF-ORDER-2", amount=10)
    assert [r["compensation_id"] for r in back2["guarantee_reversals"]] == [
        c1["compensation_id"]
    ]
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["remaining_cents"] == 100
    assert detail["ordinary_remaining_cents"] == 50
    assert detail["guarantee_outstanding_cents"] == 50
    assert client.get(f"/guarantee-funds/{fund_id}").json()["available_cents"] == 950


def test_fund_gap_blocks_new_compensation_and_later_inflows_cure_it(
    client: TestClient, wallet: Wallet
) -> None:
    agreement_id = completed_agreement(client, wallet, ["alice", "bob", "carol"], op="gap")
    r1 = client.post(
        "/receivables",
        json={
            "operation_id": "recv-gap-1",
            "receivable_no": "AR-GAP-1",
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": "d1",
            "original_creditor_id": "alice",
            "principal_cents": 100,
        },
    ).json()["receivable_id"]
    r2 = client.post(
        "/receivables",
        json={
            "operation_id": "recv-gap-2",
            "receivable_no": "AR-GAP-2",
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": "d2",
            "original_creditor_id": "bob",
            "principal_cents": 100,
        },
    ).json()["receivable_id"]
    r3 = client.post(
        "/receivables",
        json={
            "operation_id": "recv-gap-3",
            "receivable_no": "AR-GAP-3",
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": "d3",
            "original_creditor_id": "carol",
            "principal_cents": 100,
        },
    ).json()["receivable_id"]

    fund_id = create_fund(client, op="gap", amount=100)
    for idx, rid in enumerate([r1, r2, r3], start=1):
        bind(client, rid, fund_id, op=f"gap-{idx}", limit=100)

    compensate(client, r1, op="gap-a", creditor="alice", amount=100)
    client.post(
        "/disbursements",
        json={
            "operation_id": "disb-alice-gap",
            "account_id": "alice",
            "amount_cents": 100,
            "operator_account_id": "operator",
        },
    )
    paid = receipt(client, r1, serial="CH-GAP-R1", amount=100)
    compensate(client, r2, op="gap-b", creditor="bob", amount=100)

    # Ticket bounce after the recovered cash was reused for bob's compensation.
    bounced = refund(client, paid["receipt_id"], serial="RF-GAP", amount=100)
    gr = bounced["guarantee_reversals"][0]
    assert gr["deducted_available_cents"] == 0
    assert gr["gap_added_cents"] == 100
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["available_cents"] == 0
    assert fund["gap_cents"] == 100

    # Bob's compensation is valid and is not reversed/undone.
    bob_comp = client.get(f"/compensations?receivable_id={r2}").json()["compensations"][0]
    assert bob_comp["outstanding_cents"] == 100
    assert client.get("/settlement-accounts/bob").json()["available_cents"] == 100

    blocked = compensate(
        client, r3, op="gap-c-blocked", creditor="carol", amount=10, expected_status=409
    )
    assert blocked["error"]["code"] == "GUARANTEE_FUND_GAP_OUTSTANDING"

    contribution = client.post(
        f"/guarantee-funds/{fund_id}/contributions",
        json={
            "operation_id": "contrib-gap-40",
            "amount_cents": 40,
            "operator_account_id": "operator",
        },
    ).json()
    assert contribution["gap_offset_cents"] == 40
    assert contribution["fund"]["gap_cents"] == 60

    recovery60 = receipt(client, r2, serial="CH-GAP-R2-60", amount=60)
    assert recovery60["guarantee_allocations"][0]["gap_offset_cents"] == 60
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["gap_cents"] == 0
    assert fund["available_cents"] == 0

    insufficient = compensate(
        client, r3, op="gap-c-no-cash", creditor="carol", amount=10, expected_status=409
    )
    assert insufficient["error"]["code"] == "GUARANTEE_FUND_INSUFFICIENT"

    receipt(client, r2, serial="CH-GAP-R2-40", amount=40)
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["available_cents"] == 40
    ok = compensate(client, r3, op="gap-c-ok", creditor="carol", amount=10)
    assert ok["outstanding_cents"] == 10
    fund = client.get(f"/guarantee-funds/{fund_id}").json()
    assert fund["available_cents"] == 30


def test_refund_can_put_receivable_compensation_over_limit(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="overlimit")
    fund_id = create_fund(client, op="overlimit", amount=1000)
    bind(client, rid, fund_id, op="overlimit", limit=30)

    c1 = compensate(client, rid, op="ol-1", amount=30)
    first = receipt(client, rid, serial="CH-OL-1", amount=30)
    c2 = compensate(client, rid, op="ol-2", amount=30)
    refund(client, first["receipt_id"], serial="RF-OL", amount=30)

    binding = client.get(f"/receivables/{rid}").json()["guarantee_binding"]
    assert binding["outstanding_compensation_cents"] == 60
    assert binding["remaining_limit_cents"] == 0
    assert binding["over_limit_cents"] == 30
    assert binding["limit_headroom_cents"] == -30

    blocked = compensate(
        client, rid, op="ol-blocked", amount=1, expected_status=409
    )
    assert blocked["error"]["code"] == "COMPENSATION_LIMIT_EXCEEDED"

    second = receipt(client, rid, serial="CH-OL-2", amount=60)
    assert [a["compensation_id"] for a in second["guarantee_allocations"]] == [
        c1["compensation_id"],
        c2["compensation_id"],
    ]
    allowed = compensate(client, rid, op="ol-3", amount=30)
    assert allowed["amount_cents"] == 30
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["guarantee_outstanding_cents"] == 30
    assert detail["ordinary_remaining_cents"] == 10


def test_transfer_moves_only_ordinary_principal_not_subrogation(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="transfer", signers=["alice", "bob"])
    fund_id = create_fund(client, op="transfer", amount=1000)
    bind(client, rid, fund_id, op="transfer", limit=100)
    compensate(client, rid, op="transfer-comp", amount=30)

    too_much = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-too-much",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 71,
        },
    )
    assert too_much.status_code == 409
    assert too_much.json()["error"]["code"] == "TRANSFER_AMOUNT_EXCEEDS_HOLDING"

    applied = client.post(
        f"/receivables/{rid}/transfers",
        json={
            "operation_id": "trf-ordinary",
            "transferor_account_id": "alice",
            "transferee_account_id": "bob",
            "amount_cents": 70,
        },
    ).json()
    detail = client.get(f"/agreements/{applied['agreement_id']}").json()
    wallet_map = {"alice": wallet, "bob": wallet}
    for seat in detail["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{detail['agreement_id']}/seats/{seat['seat_id']}/challenges",
            json={"operation_id": f"tc-{seat['seat_id']}", "account_id": account_id},
        )
        signature = wallet_map[account_id].sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={"operation_id": f"ts-{seat['seat_id']}", "signature_b64": signature},
        )
        assert signed.status_code == 201, signed.text
    confirmed = client.post(
        f"/transfers/{applied['transfer_id']}/confirmation",
        json={"operation_id": "trf-confirm", "operator_account_id": "operator"},
    )
    assert confirmed.status_code == 200, confirmed.text

    detail = client.get(f"/receivables/{rid}").json()
    assert {h["account_id"]: h["held_cents"] for h in detail["holdings"]} == {
        "alice": 0,
        "bob": 70,
    }
    batch = detail["compensation_batches"][0]
    assert batch["creditor_account_id"] == "alice"

    paid = receipt(client, rid, serial="CH-TRF", amount=100)
    assert paid["guarantee_allocations"][0]["amount_cents"] == 30
    assert paid["allocations"][0]["account_id"] == "bob"
    assert paid["allocations"][0]["amount_cents"] == 70
    assert client.get("/settlement-accounts/bob").json()["available_cents"] == 70
    assert client.get(f"/guarantee-funds/{fund_id}").json()["available_cents"] == 1000


def test_pre_binding_receipt_refund_remains_ordinary_legacy(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="legacy")
    old_paid = receipt(client, rid, serial="CH-LEGACY-OLD", amount=10)

    fund_id = create_fund(client, op="legacy", amount=1000)
    bind(client, rid, fund_id, op="legacy", limit=100)
    compensate(client, rid, op="legacy-comp", amount=20)

    bounced = refund(client, old_paid["receipt_id"], serial="RF-LEGACY-OLD", amount=10)
    assert len(bounced["reversals"]) == 1
    assert bounced["reversals"][0]["account_id"] == "alice"
    assert bounced["guarantee_reversals"] == []

    detail = client.get(f"/receivables/{rid}").json()
    assert detail["remaining_cents"] == 100
    assert detail["ordinary_remaining_cents"] == 80
    assert detail["guarantee_outstanding_cents"] == 20
    assert client.get(f"/guarantee-funds/{fund_id}").json()["available_cents"] == 980


def test_compensation_uses_pending_deduction_before_available_balance(
    client: TestClient, wallet: Wallet
) -> None:
    rid = make_receivable(client, wallet, op="offset")
    receipt(client, rid, serial="CH-OFFSET", amount=10)
    client.post(
        "/disbursements",
        json={
            "operation_id": "dsb-offset",
            "account_id": "alice",
            "amount_cents": 8,
            "operator_account_id": "operator",
        },
    )
    refund(client, client.get(f"/receivables/{rid}").json()["receipt_ids"][0], serial="RF-OFFSET", amount=10)
    account = client.get("/settlement-accounts/alice").json()
    assert account["available_cents"] == 0
    assert account["pending_deduction_cents"] == 8

    fund_id = create_fund(client, op="offset", amount=1000)
    bind(client, rid, fund_id, op="offset", limit=100)
    comp = compensate(client, rid, op="offset-comp", amount=10)
    assert comp["deduction_offset_cents"] == 8
    assert comp["net_credited_cents"] == 2
    account = client.get("/settlement-accounts/alice").json()
    assert account["pending_deduction_cents"] == 0
    assert account["available_cents"] == 2


def test_restart_replay_does_not_duplicate_fund_or_compensation(
    tmp_path: Path, wallet: Wallet
) -> None:
    db_path = tmp_path / "restart-guarantee.db"
    app = create_app(db_path)
    with TestClient(app) as client:
        for account_id in ["operator", "alice", "initiator"]:
            wallet.add(account_id)
            client.post(
                "/accounts",
                json={
                    "operation_id": f"restart-account-{account_id}",
                    "account_id": account_id,
                    "public_key_b64": wallet.public_keys[account_id],
                },
            )
        rid = make_receivable(client, wallet, op="restart")
        # Create and fund through the real endpoints.
        created = client.post(
            "/guarantee-funds",
            json={
                "operation_id": "fund-restart-create",
                "fund_id": "fund-restart",
                "operator_account_id": "operator",
            },
        )
        assert created.status_code == 201, created.text
        contribution_body = {
            "operation_id": "fund-restart-contrib",
            "amount_cents": 500,
            "operator_account_id": "operator",
        }
        first_contrib = client.post(
            "/funds/fund-restart/contributions", json=contribution_body
        )
        assert first_contrib.status_code == 201
        bind(client, rid, "fund-restart", op="restart", limit=100)
        comp_body = {
            "operation_id": "comp-restart",
            "creditor_account_id": "alice",
            "amount_cents": 25,
            "operator_account_id": "operator",
        }
        first_comp = client.post(
            f"/receivables/{rid}/compensations", json=comp_body
        )
        assert first_comp.status_code == 201
        comp_id = first_comp.json()["compensation_id"]

    # Simulate process restart: a brand-new app/client on the same DB file.
    restarted = create_app(db_path)
    with TestClient(restarted) as client:
        replay_contrib = client.post(
            "/funds/fund-restart/contributions", json=contribution_body
        )
        assert replay_contrib.status_code == 201
        assert replay_contrib.json()["contribution_id"] == first_contrib.json()["contribution_id"]
        replay_comp = client.post(
            f"/receivables/{rid}/compensations", json=comp_body
        )
        assert replay_comp.status_code == 201
        assert replay_comp.json()["compensation_id"] == comp_id

        fund = client.get("/funds/fund-restart").json()
        assert fund["available_cents"] == 475
        assert len(fund["contributions"]) == 1
        comps = client.get(f"/compensations?receivable_id={rid}").json()["compensations"]
        assert len(comps) == 1
        assert comps[0]["compensation_id"] == comp_id


def test_legacy_ledger_schema_is_migrated_for_guarantee_events(tmp_path: Path) -> None:
    db_path = tmp_path / "old-ledger.db"
    conn = connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE settlement_ledger (
                ledger_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (event_type IN (
                    'allocation','allocation_deduction_offset',
                    'refund_clawback_balance','refund_clawback_deduction',
                    'disbursement'
                )),
                ref_type TEXT NOT NULL CHECK (ref_type IN (
                    'receipt_allocation','refund_reversal','disbursement'
                )),
                ref_id TEXT NOT NULL,
                delta_available INTEGER NOT NULL,
                delta_deduction INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                deduction_after INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO settlement_ledger VALUES (
                'old-ledger', 'alice', 'allocation', 'receipt_allocation',
                'old-alloc', 5, 0, 5, 0, '2026-01-01T00:00:00Z'
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    migrated_conn = connect(db_path)
    try:
        init_db(migrated_conn)
        row = migrated_conn.execute(
            "SELECT event_type FROM settlement_ledger WHERE ledger_id = 'old-ledger'"
        ).fetchone()
        assert row["event_type"] == "allocation"
        migrated_conn.execute(
            """
            INSERT INTO settlement_ledger VALUES (
                'new-ledger', 'alice', 'guarantee_compensation_credit',
                'guarantee_compensation', 'gcomp_x', 1, 0, 1, 0,
                '2026-01-02T00:00:00Z'
            )
            """
        )
        migrated_conn.commit()
    finally:
        migrated_conn.close()


def test_concurrent_compensations_never_overspend_fund(tmp_path: Path) -> None:
    db_path = tmp_path / "race-guarantee.db"
    app = create_app(db_path)
    wallet = Wallet()
    with TestClient(app) as client:
        for account_id in ["operator", "alice", "initiator"]:
            wallet.add(account_id)
            client.post(
                "/accounts",
                json={
                    "operation_id": f"race-account-{account_id}",
                    "account_id": account_id,
                    "public_key_b64": wallet.public_keys[account_id],
                },
            )
        rid = make_receivable(client, wallet, op="race", principal=1000)
        fund_id = create_fund(client, op="race", amount=100)
        bind(client, rid, fund_id, op="race", limit=1000)

    barrier = threading.Barrier(20)

    def worker(index: int) -> tuple[str, str]:
        barrier.wait(timeout=30)
        conn = connect(db_path)
        try:
            data = CompensationCreateRequest(
                operation_id=f"race-comp-{index}",
                receivable_id=rid,
                creditor_account_id="alice",
                amount_cents=10,
                operator_account_id="operator",
            )
            idempotent(
                conn,
                "guarantee_compensation.register",
                data.operation_id,
                {"receivable_id": rid, "body": data.model_dump()},
                lambda c: OpResult(
                    201, settlement.register_compensation_tx(c, rid, data)
                ),
            )
            return "ok", ""
        except Exception as exc:  # noqa: BLE001
            return "error", getattr(exc, "code", exc.__class__.__name__)
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=20) as pool:
        outcomes = list(pool.map(worker, range(20)))

    successes = [item for item in outcomes if item[0] == "ok"]
    failures = [item for item in outcomes if item[0] == "error"]
    assert len(successes) == 10, outcomes
    assert all(code == "GUARANTEE_FUND_INSUFFICIENT" for _, code in failures), outcomes

    conn = connect(db_path)
    try:
        fund = settlement.guarantee_fund_view(conn, fund_id)
        assert fund["available_cents"] == 0
        assert fund["gap_cents"] == 0
        outstanding = settlement._outstanding_compensation_cents(conn, rid)
        assert outstanding == 100
        ordinary = conn.execute(
            "SELECT COALESCE(SUM(held_cents), 0) AS total FROM receivable_holdings WHERE receivable_id = ?",
            (rid,),
        ).fetchone()["total"]
        assert ordinary == 900
    finally:
        conn.close()
