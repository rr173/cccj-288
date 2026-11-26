"""Automated tests for registered debtor bindings and multilateral set-off."""

from __future__ import annotations

import base64
import itertools
import random
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from signing_backend.main import create_app
from signing_backend.setoff import optimize_setoff_flows


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


ACCOUNTS = ["operator", "op2", "alice", "bob", "carol", "dave"]


class Wallet:
    def __init__(self) -> None:
        self.private_keys: dict[str, Ed25519PrivateKey] = {}
        self.public_keys: dict[str, str] = {}

    def add(self, account_id: str) -> None:
        key = Ed25519PrivateKey.generate()
        self.private_keys[account_id] = key
        self.public_keys[account_id] = b64e(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def sign(self, account_id: str, raw: bytes) -> str:
        return b64e(self.private_keys[account_id].sign(raw))


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(tmp_path / "setoff.db")
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


def completed_agreement(
    client: TestClient, wallet: Wallet, signers: list[str], *, op: str
) -> str:
    created = client.post(
        "/agreements",
        json={
            "operation_id": f"agr-create-{op}",
            "initiator_account_id": "operator",
            "title": f"基础协议 {op}",
            "content_text": "simulated receivable base agreement\n",
            "seats": [
                {"seat_key": f"seat-{name}", "original_account_id": name, "stage": 1}
                for name in signers
            ],
        },
    )
    assert created.status_code == 201, created.text
    aid = created.json()["agreement_id"]
    sent = client.post(
        f"/agreements/{aid}/send",
        json={"operation_id": f"agr-send-{op}", "initiator_account_id": "operator"},
    )
    assert sent.status_code == 200, sent.text
    for seat in sent.json()["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{aid}/seats/{seat['seat_id']}/challenges",
            json={
                "operation_id": f"agr-chal-{op}-{account_id}",
                "account_id": account_id,
            },
        )
        assert challenge.status_code == 201, challenge.text
        signature = wallet.sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={
                "operation_id": f"agr-sign-{op}-{account_id}",
                "signature_b64": signature,
            },
        )
        assert signed.status_code == 201, signed.text
    return aid


def make_receivable(
    client: TestClient,
    agreement_id: str,
    *,
    no: str,
    creditor: str,
    principal: int,
    op: str,
    debtor_account: str | None = None,
    text_debtor: str = "文字债务人",
) -> str:
    response = client.post(
        "/receivables",
        json={
            "operation_id": f"recv-{op}",
            "receivable_no": no,
            "agreement_id": agreement_id,
            "operator_account_id": "operator",
            "debtor": text_debtor,
            "original_creditor_id": creditor,
            "principal_cents": principal,
            **(
                {"debtor_account_id": debtor_account}
                if debtor_account is not None
                else {}
            ),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["receivable_id"]


def bind_debtor(
    client: TestClient,
    receivable_id: str,
    debtor: str,
    *,
    op: str,
    operator: str = "operator",
    expected_status: int = 201,
) -> dict[str, Any]:
    response = client.post(
        f"/receivables/{receivable_id}/debtor-binding",
        json={
            "operation_id": f"bind-{op}",
            "operator_account_id": operator,
            "debtor_account_id": debtor,
        },
    )
    assert response.status_code == expected_status, response.text
    return response.json()


def create_round(
    client: TestClient,
    shares: list[dict[str, Any]],
    *,
    op: str,
    expected_status: int = 201,
    operator: str = "operator",
) -> Any:
    response = client.post(
        "/setoff-rounds",
        json={
            "operation_id": f"round-{op}",
            "operator_account_id": operator,
            "items": shares,
        },
    )
    assert response.status_code == expected_status, response.text
    return response


def sign_round(client: TestClient, wallet: Wallet, round_obj: dict[str, Any]) -> None:
    aid = round_obj["agreement_id"]
    agreement = client.get(f"/agreements/{aid}").json()
    assert agreement["status"] == "active"
    for seat in agreement["seats"]:
        account_id = seat["original_account_id"]
        challenge = client.post(
            f"/agreements/{aid}/seats/{seat['seat_id']}/challenges",
            json={
                "operation_id": f"so-chal-{round_obj['round_id']}-{account_id}",
                "account_id": account_id,
            },
        )
        assert challenge.status_code == 201, challenge.text
        signature = wallet.sign(account_id, challenge.content)
        signed = client.post(
            f"/challenges/{challenge.headers['x-challenge-id']}/signature",
            json={
                "operation_id": f"so-sign-{round_obj['round_id']}-{account_id}",
                "signature_b64": signature,
            },
        )
        assert signed.status_code == 201, signed.text
    assert client.get(f"/agreements/{aid}").json()["status"] == "completed"


def confirm_round(
    client: TestClient,
    round_id: str,
    *,
    op: str,
    expected_status: int = 200,
) -> Any:
    response = client.post(
        f"/setoff-rounds/{round_id}/confirmation",
        json={"operation_id": f"confirm-{op}", "operator_account_id": "operator"},
    )
    assert response.status_code == expected_status, response.text
    return response


def holding_map(detail: dict[str, Any]) -> dict[str, int]:
    return {h["account_id"]: h["held_cents"] for h in detail["holdings"]}


def availability_map(detail: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        h["account_id"]: {
            "held": h["held_cents"],
            "occupied": h["occupied_cents"],
            "available": h["available_cents"],
        }
        for h in detail["holding_availability"]
    }


# ---------------------------------------------------------------------------
# Pure optimizer
# ---------------------------------------------------------------------------


def brute_optimize(edges: list[tuple[str, str, int]]) -> list[int]:
    caps = [edge[2] for edge in edges]
    best_score: tuple[int, ...] | None = None
    best_xs: tuple[int, ...] | None = None
    for xs in itertools.product(*[range(cap + 1) for cap in caps]):
        balance: dict[str, int] = {}
        for (debtor, creditor, _), amount in zip(edges, xs):
            balance[debtor] = balance.get(debtor, 0) - amount
            balance[creditor] = balance.get(creditor, 0) + amount
        if any(value != 0 for value in balance.values()):
            continue
        score = (sum(xs), *xs)
        if best_score is None or score > best_score:
            best_score = score
            best_xs = xs
    assert best_xs is not None
    return list(best_xs)


def test_optimizer_matches_brute_force_and_lex_tie_break() -> None:
    for seed in range(3000):
        rng = random.Random(seed)
        accounts = ["a", "b", "c", "d"][: rng.randint(2, 4)]
        edges: list[tuple[str, str, int]] = []
        for _ in range(rng.randint(1, 7)):
            debtor = rng.choice(accounts)
            creditor = rng.choice(accounts)
            if debtor != creditor:
                edges.append((debtor, creditor, rng.randint(0, 3)))
        assert optimize_setoff_flows(edges) == brute_optimize(edges)

    # Parallel account edges create a direct lexicographic allocation tie.
    edges = [("a", "b", 5), ("a", "b", 5), ("b", "a", 3)]
    assert optimize_setoff_flows(edges) == [3, 0, 3]


# ---------------------------------------------------------------------------
# Debtor binding
# ---------------------------------------------------------------------------


def test_debtor_binding_permission_once_and_availability_view(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="bind-base")
    rid = make_receivable(
        client, aid, no="AR-BIND", creditor="alice", principal=100, op="bind"
    )

    forbidden = bind_debtor(
        client, rid, "bob", op="wrong-operator", operator="alice", expected_status=403
    )
    assert forbidden["error"]["code"] == "NOT_RECEIVABLE_OPERATOR"

    binding = bind_debtor(client, rid, "bob", op="ok")
    assert binding["debtor_account_id"] == "bob"
    assert binding["receivable_id"] == rid

    again = bind_debtor(client, rid, "carol", op="again", expected_status=409)
    assert again["error"]["code"] == "RECEIVABLE_DEBTOR_ALREADY_BOUND"

    detail = client.get(f"/receivables/{rid}").json()
    assert detail["bound_debtor_account_id"] == "bob"
    assert detail["debtor_binding"]["binding_id"] == binding["binding_id"]
    assert availability_map(detail)["alice"] == {
        "held": 100,
        "occupied": 0,
        "available": 100,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_three_party_setoff_sign_confirm_write_down_without_money_flows(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(
        client, wallet, ["alice", "bob", "carol"], op="cycle-base"
    )
    # alice's receivable is owed by bob.
    r_ab = make_receivable(
        client, aid, no="AR-A-B", creditor="alice", principal=100, op="ab",
        debtor_account="bob",
    )
    # bob's receivable is owed by carol.
    r_bc = make_receivable(
        client, aid, no="AR-B-C", creditor="bob", principal=80, op="bc",
        debtor_account="carol",
    )
    # carol's receivable is owed by alice.
    r_ca = make_receivable(
        client, aid, no="AR-C-A", creditor="carol", principal=60, op="ca",
        debtor_account="alice",
    )

    created = create_round(
        client,
        [
            {"receivable_id": r_ab, "creditor_account_id": "alice", "limit_cents": 90},
            {"receivable_id": r_bc, "creditor_account_id": "bob", "limit_cents": 80},
            {"receivable_id": r_ca, "creditor_account_id": "carol", "limit_cents": 70},
        ],
        op="cycle-round",
    ).json()
    rid = created["round_id"]
    assert created["status"] == "pending"
    assert created["total_offset_cents"] == 60 * 3
    assert [item["offset_cents"] for item in created["items"]] == [60, 60, 60]
    assert created["participant_accounts"] == ["alice", "bob", "carol"]
    assert created["agreement_status"] == "active"
    assert created["seat_count"] == 3

    # Creation occupies only selected principal, not the requested caps.
    availability = {
        no: availability_map(client.get(f"/receivables/{rec}").json())
        for no, rec in [("ab", r_ab), ("bc", r_bc), ("ca", r_ca)]
    }
    assert availability["ab"]["alice"]["occupied"] == 60
    assert availability["ab"]["alice"]["available"] == 40
    assert availability["bc"]["bob"]["available"] == 20
    assert availability["ca"]["carol"]["available"] == 0

    # Before signatures, confirmation is rejected without changing principal.
    early = confirm_round(client, rid, op="early", expected_status=409)
    assert early.json()["error"]["code"] == "SETOFF_AGREEMENT_NOT_COMPLETED"

    sign_round(client, wallet, created)
    confirmed = confirm_round(client, rid, op="ok").json()
    assert confirmed["status"] == "effective"
    assert confirmed["effective_at"]

    for rec, expected in [(r_ab, 40), (r_bc, 20), (r_ca, 0)]:
        detail = client.get(f"/receivables/{rec}").json()
        assert detail["remaining_cents"] == expected
        assert sum(h["held_cents"] for h in detail["holdings"]) == expected
        assert detail["occupied_ordinary_cents"] == 0
        assert detail["available_ordinary_cents"] == expected

    # No set-off credits settlement accounts or appends ledger entries.
    for account in ["alice", "bob", "carol"]:
        view = client.get(f"/settlement-accounts/{account}").json()
        assert view["available_cents"] == 0
        assert view["ledger"] == []

    second = confirm_round(client, rid, op="second-new-op", expected_status=409)
    assert second.json()["error"]["code"] == "SETOFF_ROUND_ALREADY_EFFECTIVE"


def test_confirm_operation_replay_returns_original_effective_result(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="replay-base")
    r1 = make_receivable(
        client, aid, no="AR-R1", creditor="alice", principal=10, op="r1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-R2", creditor="bob", principal=10, op="r2",
        debtor_account="alice",
    )
    round_obj = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 10},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 10},
        ],
        op="replay-round",
    ).json()
    sign_round(client, wallet, round_obj)
    body = {"operation_id": "exact-confirm-op", "operator_account_id": "operator"}
    first = client.post(
        f"/setoff-rounds/{round_obj['round_id']}/confirmation", json=body
    )
    assert first.status_code == 200, first.text
    second = client.post(
        f"/setoff-rounds/{round_obj['round_id']}/confirmation", json=body
    )
    assert second.status_code == 200
    assert second.json()["effective_at"] == first.json()["effective_at"]


def test_no_positive_plan_creates_no_agreement_or_occupation(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="zero-base")
    rid = make_receivable(
        client, aid, no="AR-Z", creditor="alice", principal=10, op="zero",
        debtor_account="bob",
    )
    response = create_round(
        client,
        [{"receivable_id": rid, "creditor_account_id": "alice", "limit_cents": 10}],
        op="zero-round",
        expected_status=409,
    )
    assert response.json()["error"]["code"] == "NO_POSITIVE_SETOFF_PLAN"
    detail = client.get(f"/receivables/{rid}").json()
    assert detail["occupied_ordinary_cents"] == 0
    assert client.get("/setoff-rounds").json()["rounds"] == []


def test_duplicate_and_self_claims_are_handled(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="dup-base")
    self_rid = make_receivable(
        client, aid, no="AR-SELF", creditor="alice", principal=10, op="self",
        debtor_account="alice",
    )
    r1 = make_receivable(
        client, aid, no="AR-DUP", creditor="bob", principal=10, op="dup",
        debtor_account="alice",
    )

    # A list containing only a self claim has no positive plan.
    create_round(
        client,
        [{"receivable_id": self_rid, "creditor_account_id": "alice", "limit_cents": 10}],
        op="self-only",
        expected_status=409,
    )

    # Duplicate receivable+creditor is rejected even if caps differ.
    dup = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "bob", "limit_cents": 5},
            {"receivable_id": r1, "creditor_account_id": "bob", "limit_cents": 4},
        ],
        op="dup-round",
        expected_status=409,
    )
    assert dup.json()["error"]["code"] == "SETOFF_DUPLICATE_SHARE"


def sign_transfer_agreement(
    client: TestClient, wallet: Wallet, transfer: dict[str, Any]
) -> None:
    detail = client.get(f"/agreements/{transfer['agreement_id']}").json()
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


def test_list_order_tie_break_uses_first_share(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="tie-base")
    r1 = make_receivable(
        client, aid, no="AR-TIE-1", creditor="bob", principal=5, op="tie1",
        debtor_account="alice",
    )
    r2 = make_receivable(
        client, aid, no="AR-TIE-2", creditor="bob", principal=5, op="tie2",
        debtor_account="alice",
    )
    r3 = make_receivable(
        client, aid, no="AR-TIE-3", creditor="alice", principal=3, op="tie3",
        debtor_account="bob",
    )
    round_obj = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "bob", "limit_cents": 5},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 5},
            {"receivable_id": r3, "creditor_account_id": "alice", "limit_cents": 3},
        ],
        op="tie-round",
    ).json()
    assert [item["offset_cents"] for item in round_obj["items"]] == [3, 0, 3]
    assert round_obj["total_offset_cents"] == 6

    r1_view = client.get(f"/receivables/{r1}").json()
    r2_view = client.get(f"/receivables/{r2}").json()
    assert availability_map(r1_view)["bob"]["occupied"] == 3
    assert availability_map(r2_view)["bob"]["occupied"] == 0


def test_pending_occupation_blocks_transfer_and_compensation_but_not_receipt(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(
        client, wallet, ["alice", "bob", "carol"], op="block-base"
    )
    r1 = make_receivable(
        client, aid, no="AR-BLOCK-1", creditor="alice", principal=100, op="block1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-BLOCK-2", creditor="bob", principal=100, op="block2",
        debtor_account="alice",
    )
    round_obj = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 60},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 100},
        ],
        op="block-round",
    ).json()
    assert [i["offset_cents"] for i in round_obj["items"]] == [60, 60]

    # A 50-cent transfer would use 10 cents of the occupied 60.
    applied = client.post(
        f"/receivables/{r1}/transfers",
        json={
            "operation_id": "apply-blocked-transfer",
            "transferor_account_id": "alice",
            "transferee_account_id": "carol",
            "amount_cents": 50,
        },
    )
    assert applied.status_code == 201, applied.text
    transfer = applied.json()
    sign_transfer_agreement(client, wallet, transfer)
    blocked = client.post(
        f"/transfers/{transfer['transfer_id']}/confirmation",
        json={"operation_id": "confirm-blocked-transfer", "operator_account_id": "operator"},
    )
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "TRANSFER_AMOUNT_OCCUPIED_BY_SETOFF"
    assert client.get(f"/transfers/{transfer['transfer_id']}").json()["status"] == "pending"

    # A transfer inside the 40-cent unoccupied slice can become effective.
    small = client.post(
        f"/receivables/{r1}/transfers",
        json={
            "operation_id": "apply-small-transfer",
            "transferor_account_id": "alice",
            "transferee_account_id": "carol",
            "amount_cents": 40,
        },
    ).json()
    sign_transfer_agreement(client, wallet, small)
    confirmed = client.post(
        f"/transfers/{small['transfer_id']}/confirmation",
        json={"operation_id": "confirm-small-transfer", "operator_account_id": "operator"},
    )
    assert confirmed.status_code == 200, confirmed.text
    r1_detail = client.get(f"/receivables/{r1}").json()
    assert holding_map(r1_detail) == {"alice": 60, "carol": 40}
    assert availability_map(r1_detail)["alice"]["available"] == 0

    # Compensation also cannot touch the occupied slice.
    fund = client.post(
        "/guarantee-funds",
        json={"operation_id": "fund-block", "fund_id": "fund-block", "operator_account_id": "operator"},
    ).json()
    client.post(
        f"/guarantee-funds/{fund['fund_id']}/contributions",
        json={"operation_id": "fund-block-money", "amount_cents": 1000, "operator_account_id": "operator"},
    )
    bound = client.post(
        f"/receivables/{r1}/guarantee-binding",
        json={
            "operation_id": "fund-bind-block",
            "fund_id": fund["fund_id"],
            "limit_cents": 1000,
            "operator_account_id": "operator",
        },
    )
    assert bound.status_code == 201, bound.text
    bad_comp = client.post(
        f"/receivables/{r1}/compensations",
        json={
            "operation_id": "comp-bad",
            "creditor_account_id": "alice",
            "amount_cents": 1,
            "operator_account_id": "operator",
        },
    )
    assert bad_comp.status_code == 409
    assert bad_comp.json()["error"]["code"] == "COMPENSATION_PRINCIPAL_OCCUPIED_BY_SETOFF"


def test_receipt_coverage_keeps_earlier_round_and_releases_later_round(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="cover-base")
    shared = make_receivable(
        client, aid, no="AR-SHARED", creditor="alice", principal=15, op="shared",
        debtor_account="bob",
    )
    bob_old = make_receivable(
        client, aid, no="AR-BOB-OLD", creditor="bob", principal=10, op="bob-old",
        debtor_account="alice",
    )
    bob_new_other = make_receivable(
        client, aid, no="AR-BOB-NEW", creditor="bob", principal=5, op="bob-new",
        debtor_account="alice",
    )

    old_round = create_round(
        client,
        [
            {"receivable_id": shared, "creditor_account_id": "alice", "limit_cents": 10},
            {"receivable_id": bob_old, "creditor_account_id": "bob", "limit_cents": 10},
        ],
        op="old-round",
    ).json()
    new_round = create_round(
        client,
        [
            {"receivable_id": shared, "creditor_account_id": "alice", "limit_cents": 5},
            {"receivable_id": bob_new_other, "creditor_account_id": "bob", "limit_cents": 5},
        ],
        op="new-round",
    ).json()

    other_before = client.get(f"/receivables/{bob_new_other}").json()
    assert availability_map(other_before)["bob"]["occupied"] == 5

    receipt = client.post(
        f"/receivables/{shared}/receipts",
        json={
            "operation_id": "receipt-coverage",
            "channel_serial_no": "CH-COVERAGE",
            "amount_cents": 5,
            "operator_account_id": "operator",
        },
    )
    assert receipt.status_code == 201, receipt.text
    assert receipt.json()["invalidated_setoff_round_ids"] == [new_round["round_id"]]

    old_view = client.get(f"/setoff-rounds/{old_round['round_id']}").json()
    new_view = client.get(f"/setoff-rounds/{new_round['round_id']}").json()
    assert old_view["status"] == "pending"
    assert old_view["coverage_ok"] is True
    assert new_view["status"] == "invalid"
    assert new_view["termination_reason_code"] == "SETOFF_COVERAGE_LOST"
    assert client.get(f"/agreements/{new_round['agreement_id']}").json()["status"] == "cancelled"

    other_after = client.get(f"/receivables/{bob_new_other}").json()
    assert availability_map(other_after)["bob"] == {
        "held": 5,
        "occupied": 0,
        "available": 5,
    }

    # The unsigned seats of the invalid agreement can no longer produce signatures.
    seat = new_view["seats"][0]
    challenge = client.post(
        f"/agreements/{new_round['agreement_id']}/seats/{seat['seat_id']}/challenges",
        json={"operation_id": "late-challenge", "account_id": seat["account_id"]},
    )
    assert challenge.status_code == 409
    assert challenge.json()["error"]["code"] == "AGREEMENT_NOT_ACTIVE"

    # Refund restores principal but does not revive the invalid round.
    refund = client.post(
        f"/receipts/{receipt.json()['receipt_id']}/refunds",
        json={
            "operation_id": "refund-coverage",
            "channel_serial_no": "RF-COVERAGE",
            "amount_cents": 5,
            "operator_account_id": "operator",
        },
    )
    assert refund.status_code == 201, refund.text
    assert client.get(f"/setoff-rounds/{new_round['round_id']}").json()["status"] == "invalid"
    confirm_bad = confirm_round(
        client, new_round["round_id"], op="confirm-invalid", expected_status=409
    )
    assert confirm_bad.json()["error"]["code"] == "SETOFF_ROUND_INVALID"

    # The older retained round can still be signed and made effective.
    sign_round(client, wallet, old_view)
    assert confirm_round(client, old_round["round_id"], op="confirm-old").status_code == 200


def test_agreement_cancellation_and_operator_revocation_release_occupations(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="cancel-base")
    r1 = make_receivable(
        client, aid, no="AR-CAN-1", creditor="alice", principal=10, op="can1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-CAN-2", creditor="bob", principal=10, op="can2",
        debtor_account="alice",
    )
    round1 = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 10},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 10},
        ],
        op="cancel-round",
    ).json()

    cancelled = client.post(
        f"/agreements/{round1['agreement_id']}/cancellation",
        json={"operation_id": "cancel-setoff-agreement", "initiator_account_id": "operator"},
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["setoff_round"]["status"] == "revoked"
    assert client.get(f"/setoff-rounds/{round1['round_id']}").json()["status"] == "revoked"
    assert client.get(f"/receivables/{r1}").json()["occupied_ordinary_cents"] == 0
    confirm = confirm_round(
        client, round1["round_id"], op="confirm-cancelled", expected_status=409
    )
    assert confirm.json()["error"]["code"] == "SETOFF_ROUND_REVOKED"

    round2 = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 7},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 7},
        ],
        op="revoke-round",
    ).json()
    revoked = client.post(
        f"/setoff-rounds/{round2['round_id']}/revocation",
        json={
            "operation_id": "revoke-round-op",
            "operator_account_id": "operator",
            "reason": "operator changed mind",
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert client.get(f"/agreements/{round2['agreement_id']}").json()["status"] == "cancelled"
    assert client.get(f"/receivables/{r1}").json()["occupied_ordinary_cents"] == 0


def test_refund_does_not_reverse_effective_setoff(
    client: TestClient, wallet: Wallet
) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="refund-eff-base")
    r1 = make_receivable(
        client, aid, no="AR-REF-EFF-1", creditor="alice", principal=100, op="refeff1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-REF-EFF-2", creditor="bob", principal=60, op="refeff2",
        debtor_account="alice",
    )
    receipt = client.post(
        f"/receivables/{r1}/receipts",
        json={
            "operation_id": "receipt-before-setoff",
            "channel_serial_no": "CH-BEFORE-SETOFF",
            "amount_cents": 40,
            "operator_account_id": "operator",
        },
    )
    assert receipt.status_code == 201, receipt.text

    round_obj = create_round(
        client,
        [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 60},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 60},
        ],
        op="refund-effective-round",
    ).json()
    sign_round(client, wallet, round_obj)
    assert confirm_round(client, round_obj["round_id"], op="refund-eff-confirm").status_code == 200
    assert client.get(f"/receivables/{r1}").json()["remaining_cents"] == 0

    refund = client.post(
        f"/receipts/{receipt.json()['receipt_id']}/refunds",
        json={
            "operation_id": "refund-after-effective-setoff",
            "channel_serial_no": "RF-AFTER-SETOFF",
            "amount_cents": 40,
            "operator_account_id": "operator",
        },
    )
    assert refund.status_code == 201, refund.text
    r1_detail = client.get(f"/receivables/{r1}").json()
    assert r1_detail["remaining_cents"] == 40
    assert holding_map(r1_detail) == {"alice": 40}
    round_view = client.get(f"/setoff-rounds/{round_obj['round_id']}").json()
    assert round_view["status"] == "effective"
    assert [i["offset_cents"] for i in round_view["items"]] == [60, 60]


def test_restart_replays_round_and_confirmation_without_double_effect(
    client: TestClient, wallet: Wallet
) -> None:
    db_path = client.app.state.db_path
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="restart-base")
    r1 = make_receivable(
        client, aid, no="AR-RESTART-1", creditor="alice", principal=10, op="restart1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-RESTART-2", creditor="bob", principal=10, op="restart2",
        debtor_account="alice",
    )
    body = {
        "operation_id": "restart-round-op",
        "operator_account_id": "operator",
        "items": [
            {"receivable_id": r1, "creditor_account_id": "alice", "limit_cents": 10},
            {"receivable_id": r2, "creditor_account_id": "bob", "limit_cents": 10},
        ],
    }
    first = client.post("/setoff-rounds", json=body)
    assert first.status_code == 201, first.text
    round_id = first.json()["round_id"]

    with TestClient(create_app(db_path)) as client2:
        replay = client2.post("/setoff-rounds", json=body)
        assert replay.status_code == 201
        assert replay.json()["round_id"] == round_id
        assert client2.get("/setoff-rounds").json()["rounds"].__len__() == 1
        sign_round(client2, wallet, replay.json())
        confirm_body = {
            "operation_id": "restart-confirm-op",
            "operator_account_id": "operator",
        }
        confirmed = client2.post(f"/setoff-rounds/{round_id}/confirmation", json=confirm_body)
        assert confirmed.status_code == 200, confirmed.text

    with TestClient(create_app(db_path)) as client3:
        replay_confirm = client3.post(
            f"/setoff-rounds/{round_id}/confirmation", json=confirm_body
        )
        assert replay_confirm.status_code == 200
        assert replay_confirm.json()["status"] == "effective"
        r1_detail = client3.get(f"/receivables/{r1}").json()
        assert r1_detail["remaining_cents"] == 0
        assert holding_map(r1_detail) == {"alice": 0}


def test_http_and_field_naming_aliases(client: TestClient, wallet: Wallet) -> None:
    aid = completed_agreement(client, wallet, ["alice", "bob"], op="alias-base")
    r1 = make_receivable(
        client, aid, no="AR-ALIAS-1", creditor="alice", principal=4, op="alias1",
        debtor_account="bob",
    )
    r2 = make_receivable(
        client, aid, no="AR-ALIAS-2", creditor="bob", principal=4, op="alias2",
        debtor_account="alice",
    )
    response = client.post(
        "/debt-setoffs",
        json={
            "operation_id": "alias-round-op",
            "initiator_account_id": "operator",
            "shares": [
                {"receivable_id": r1, "creditor_id": "alice", "max_amount_cents": 4},
                {"receivable_id": r2, "creditor_id": "bob", "upper_limit_cents": 4},
            ],
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["id"].startswith("setoff_")
    assert [item["amount_cents"] for item in body["offsets"]] == [4, 4]
    fetched = client.get(f"/offset-rounds/{body['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["total_setoff_amount_cents"] == 8
