#!/usr/bin/env python3
"""End-to-end HTTP demo for multilateral debt set-off (多方债务抵销).

The script assumes a server is already running; ``run_setoff_demo.sh`` starts a
local temporary server and invokes this file.  All amounts are integer cents in
one simulated currency.  No bank or payment channel is used.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from client_lib import KeyStore, SigningClient  # noqa: E402


def heading(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def sign_agreement(
    client: SigningClient, store: KeyStore, agreement_id: str, run_id: str
) -> None:
    detail = client.get_agreement(agreement_id)
    for seat in detail["seats"]:
        account_id = seat["original_account_id"]
        signer = store.load(account_id)
        client.sign_challenge(
            agreement_id,
            seat["seat_id"],
            signer,
            challenge_op=f"setoff-demo-chal-{agreement_id}-{account_id}-{run_id}",
            signature_op=f"setoff-demo-sign-{agreement_id}-{account_id}-{run_id}",
        )
    assert client.get_agreement(agreement_id)["status"] == "completed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    workdir = Path(args.workdir)
    keys_dir = workdir / "keys"
    run_id = uuid.uuid4().hex[:10]
    operator = "operator"
    accounts = [operator, "alice", "bob", "carol"]

    store = KeyStore(keys_dir)
    for account in accounts:
        store.load_or_create(account)

    snapshot: dict[str, Any] = {"run_id": run_id}
    with SigningClient(args.base_url) as client:
        heading("0. 健康检查并登记本机模拟账号")
        print(client.health())
        for account in accounts:
            client.register(
                store.load(account), op_id=f"register-{account}-{run_id}"
            )

        heading("1. 准备一份已完成的基础应收协议")
        base = client.create_agreement(
            initiator=operator,
            title=f"多方抵销基础协议 {run_id}",
            content_text=f"base agreement for set-off demo {run_id}\n",
            seats=[
                {"seat_key": name, "original_account_id": name, "stage": 1}
                for name in ["alice", "bob", "carol"]
            ],
            op_id=f"base-create-{run_id}",
        )
        client.send(base["agreement_id"], operator, op_id=f"base-send-{run_id}")
        sign_agreement(client, store, base["agreement_id"], run_id)
        base_aid = base["agreement_id"]
        print("completed base agreement:", base_aid)

        heading("2. 登记三笔首尾相接的应收，并直接绑定已登记债务人账号")
        # alice is owed by bob; bob is owed by carol; carol is owed by alice.
        receivable_specs = [
            ("AR-AB", "alice", "bob", 1000),
            ("AR-BC", "bob", "carol", 800),
            ("AR-CA", "carol", "alice", 600),
        ]
        receivables: list[dict[str, Any]] = []
        for index, (no, creditor, debtor, principal) in enumerate(receivable_specs):
            rec = client.request_json(
                "POST",
                "/receivables",
                {
                    "operation_id": f"recv-{no}-{run_id}",
                    "receivable_no": f"{no}-{run_id}",
                    "agreement_id": base_aid,
                    "operator_account_id": operator,
                    "debtor": f"文字债务人-{debtor}",
                    "original_creditor_id": creditor,
                    "principal_cents": principal,
                    "debtor_account_id": debtor,
                },
            )
            receivables.append(rec)
            print(no, rec["receivable_id"], "bound debtor:", debtor)

        heading("3. 发起多方抵销：最大平衡额为 600 分，三项各抵销 600 分")
        round_body = {
            "operation_id": f"setoff-create-{run_id}",
            "operator_account_id": operator,
            "items": [
                {
                    "receivable_id": receivables[0]["receivable_id"],
                    "creditor_account_id": "alice",
                    "limit_cents": 900,
                },
                {
                    "receivable_id": receivables[1]["receivable_id"],
                    "creditor_account_id": "bob",
                    "limit_cents": 800,
                },
                {
                    "receivable_id": receivables[2]["receivable_id"],
                    "creditor_account_id": "carol",
                    "limit_cents": 700,
                },
            ],
        }
        round_view = client.request_json("POST", "/setoff-rounds", round_body, expected={201})
        round_id = round_view["round_id"]
        snapshot["round_created"] = round_view
        print("round:", round_id, "agreement:", round_view["agreement_id"])
        print(
            "offsets:",
            [(item["creditor_account_id"], item["offset_cents"]) for item in round_view["items"]],
        )

        heading("4. 查看应收普通本金中的占用与可用部分")
        availability = []
        for rec in receivables:
            detail = client.get_receivable(rec["receivable_id"])
            availability.append(
                {
                    "receivable_no": detail["receivable_no"],
                    "remaining_cents": detail["remaining_cents"],
                    "ordinary_held": detail["ordinary_remaining_cents"],
                    "occupied": detail["occupied_ordinary_cents"],
                    "available": detail["available_ordinary_cents"],
                    "holdings": detail["holding_availability"],
                }
            )
        snapshot["availability_before_confirmation"] = availability
        print(json.dumps(availability, ensure_ascii=False, indent=2))

        heading("5. 三个参与账号通过现有挑战/签名流程签署专用协议")
        sign_agreement(client, store, round_view["agreement_id"], run_id)
        signed_round = client.request_json("GET", f"/setoff-rounds/{round_id}")
        assert signed_round["agreement_status"] == "completed"
        print("signed seats:", signed_round["signed_count"], "/", signed_round["seat_count"])

        heading("6. 运营确认：一次性减记，无到账/入款/基金流水")
        effective = client.request_json(
            "POST",
            f"/setoff-rounds/{round_id}/confirmation",
            {
                "operation_id": f"setoff-confirm-{run_id}",
                "operator_account_id": operator,
            },
            expected={200},
        )
        snapshot["round_effective"] = effective
        print("status:", effective["status"], "total offset:", effective["total_offset_cents"])

        final_receivables = []
        for rec in receivables:
            detail = client.get_receivable(rec["receivable_id"])
            final_receivables.append(
                {
                    "receivable_id": detail["receivable_id"],
                    "receivable_no": detail["receivable_no"],
                    "remaining_cents": detail["remaining_cents"],
                    "holdings": detail["holdings"],
                }
            )
        snapshot["final_receivables"] = final_receivables
        snapshot["settlement_accounts"] = {
            account: client.request_json("GET", f"/settlement-accounts/{account}")
            for account in ["alice", "bob", "carol"]
        }
        print(json.dumps(final_receivables, ensure_ascii=False, indent=2))
        for account in ["alice", "bob", "carol"]:
            account_view = snapshot["settlement_accounts"][account]
            assert account_view["available_cents"] == 0
            assert account_view["ledger"] == []
        print("confirmed: no settlement-account balances or ledger movements were created")

        write_json(workdir / "setoff-demo-snapshot.json", snapshot)
        print("\nsnapshot saved:", workdir / "setoff-demo-snapshot.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
