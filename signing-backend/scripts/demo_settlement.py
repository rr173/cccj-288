#!/usr/bin/env python3
"""End-to-end HTTP demonstration of receivable settlement (应收款结算).

Runs against an already-started server (see run_settlement_demo.sh):

  1. complete a base signing agreement through the existing signing flow;
  2. register a receivable (receivable number, debtor, original creditor,
     integer-cent principal) under the completed agreement;
  3. apply for a principal transfer, sign the generated transfer agreement
     with the existing challenge flow, and let the operator confirm it;
  4. register channel receipts and inspect the largest-remainder split;
  5. register partial refunds and observe original-line clawback, balance
     deduction and pending deduction offsets;
  6. register disbursements limited by drawable balance;
  7. print holdings, receipt/refund details and settlement accounts.

All money is simulated integer cents; no bank or payment network is involved.
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

from client_lib import ApiCallError, KeyStore, SigningClient  # noqa: E402


def heading(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def sign_agreement(client: SigningClient, store: KeyStore, agreement_id: str, run_id: str) -> None:
    detail = client.get_agreement(agreement_id)
    for seat in detail["seats"]:
        account_id = seat["original_account_id"]
        signer = store.load(account_id)
        client.sign_challenge(
            agreement_id,
            seat["seat_id"],
            signer,
            challenge_op=f"chal-{agreement_id}-{account_id}-{run_id}",
            signature_op=f"sign-{agreement_id}-{account_id}-{run_id}",
        )
    assert client.get_agreement(agreement_id)["status"] == "completed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    keys_dir = workdir / "keys"
    run_id = uuid.uuid4().hex[:10]
    operator = "operator"

    store = KeyStore(keys_dir)
    accounts = ["alice", "bob", "carol", "initiator", operator]
    signers = {name: store.load_or_create(name) for name in accounts}

    with SigningClient(args.base_url) as client:
        heading("0. 健康检查并登记公钥")
        print(client.health())
        for name in accounts:
            client.register(signers[name], op_id=f"register-{name}-{run_id}")

        heading("1. 走完现有签署流程，得到一份已完成的基础协议")
        base = client.create_agreement(
            initiator="initiator",
            title="应收款基础债权协议",
            content_text=f"基础协议正文 {run_id}\n",
            seats=[
                {"seat_key": "creditor", "original_account_id": "alice", "stage": 1},
            ],
            op_id=f"create-base-{run_id}",
        )
        base_aid = base["agreement_id"]
        client.send(base_aid, "initiator", op_id=f"send-base-{run_id}")
        sign_agreement(client, store, base_aid, run_id)
        print("base agreement completed:", base_aid)

        heading("2. 运营登记应收款（整数分本金，单币种模拟）")
        receivable = client.register_receivable(
            receivable_no=f"AR-{run_id}",
            agreement_id=base_aid,
            operator=operator,
            debtor="债务人示例-甲",
            original_creditor="alice",
            principal_cents=1000,
            op_id=f"recv-{run_id}",
        )
        rid = receivable["receivable_id"]
        print(json.dumps(receivable, ensure_ascii=False, indent=2))

        heading("3. 债权人申请转让 400 分给 carol；服务生成转让协议并由两方签署")
        transfer = client.apply_transfer(
            rid,
            transferor="alice",
            transferee="carol",
            amount_cents=400,
            op_id=f"trf-apply-{run_id}",
        )
        transfer_id = transfer["transfer_id"]
        print("transfer application:", transfer_id, "agreement:", transfer["agreement_id"])
        sign_agreement(client, store, transfer["agreement_id"], run_id)

        heading("4. 运营确认转让（只认已完成协议，按当时未收本金判定）")
        confirmed = client.confirm_transfer(
            transfer_id, operator, op_id=f"trf-confirm-{run_id}"
        )
        print("transfer status:", confirmed["status"])
        detail = client.get_receivable(rid)
        print("holdings:", {h["account_id"]: h["held_cents"] for h in detail["holdings"]})

        heading("5. 渠道到账 300 分，按到账前持有比例最大余数法分款")
        receipt1 = client.register_receipt(
            rid,
            channel_serial_no=f"CH-{run_id}-1",
            amount_cents=300,
            operator=operator,
            op_id=f"rcpt-1-{run_id}",
        )
        print(
            "allocations:",
            {a["account_id"]: a["amount_cents"] for a in receipt1["allocations"]},
        )
        # alice 180 / carol 120.  alice draws 150 out before any refund, so the
        # later clawback cannot fully recover from her drawable balance.
        client.register_disbursement(
            account_id="alice",
            amount_cents=150,
            operator=operator,
            note="payout before refund",
            op_id=f"dsb-before-refund-{run_id}",
        )
        print(
            "alice available after drawing 150:",
            client.settlement_account("alice")["available_cents"],
        )

        heading("6. 再到账 100 分；相同请求重试不会重复记账")
        payload_op = f"rcpt-2-{run_id}"
        receipt2 = client.register_receipt(
            rid,
            channel_serial_no=f"CH-{run_id}-2",
            amount_cents=100,
            operator=operator,
            op_id=payload_op,
        )
        replay = client.register_receipt(
            rid,
            channel_serial_no=f"CH-{run_id}-2",
            amount_cents=100,
            operator=operator,
            op_id=payload_op,
        )
        assert receipt2["receipt_id"] == replay["receipt_id"]
        print("replay returned same receipt_id:", replay["receipt_id"])

        # Same channel serial with different content must be rejected.
        try:
            client.register_receipt(
                rid,
                channel_serial_no=f"CH-{run_id}-2",
                amount_cents=999,
                operator=operator,
                op_id=f"rcpt-conflict-{run_id}",
            )
        except ApiCallError as exc:
            print("[预期拒绝] 同流水号换内容:", exc.code)

        heading("7. 分次退票：先退 150 分，再退剩余部分；按原分款行冲回")
        refund1 = client.register_refund(
            receipt1["receipt_id"],
            channel_serial_no=f"RF-{run_id}-1",
            amount_cents=150,
            operator=operator,
            op_id=f"rfnd-1-{run_id}",
        )
        print(
            "refund 1 reversals:",
            [
                (
                    r["account_id"],
                    r["amount_cents"],
                    f"balance={r['clawback_from_balance_cents']}",
                    f"deduction={r['clawback_to_deduction_cents']}",
                )
                for r in refund1["reversals"]
            ],
        )
        remaining_refund = receipt1["amount_cents"] - 150
        refund2 = client.register_refund(
            receipt1["receipt_id"],
            channel_serial_no=f"RF-{run_id}-2",
            amount_cents=remaining_refund,
            operator=operator,
            op_id=f"rfnd-2-{run_id}",
        )
        print(
            "refund 2 reversals:",
            [
                (
                    r["account_id"],
                    r["amount_cents"],
                    f"balance={r['clawback_from_balance_cents']}",
                    f"deduction={r['clawback_to_deduction_cents']}",
                )
                for r in refund2["reversals"]
            ],
        )
        write_json(workdir / "receipt-1.json", client.get_receipt(receipt1["receipt_id"]))
        alice_account = client.settlement_account("alice")
        print(
            "alice pending deduction after full refund:",
            alice_account["pending_deduction_cents"],
        )

        heading("8. 划款不得超过可划余额；新分款先抵扣待扣回欠额")
        # Another receipt: alice's gross share first offsets her clawback debt.
        receipt3 = client.register_receipt(
            rid,
            channel_serial_no=f"CH-{run_id}-3",
            amount_cents=100,
            operator=operator,
            op_id=f"rcpt-3-{run_id}",
        )
        for allocation in receipt3["allocations"]:
            if allocation["account_id"] == "alice":
                print(
                    "alice gross share:",
                    allocation["amount_cents"],
                    "deduction offset:",
                    allocation["deduction_offset_cents"],
                    "net credited:",
                    allocation["net_credited_cents"],
                )
        print(
            "alice available / pending now:",
            client.settlement_account("alice")["available_cents"],
            "/",
            client.settlement_account("alice")["pending_deduction_cents"],
        )

        heading("9. 查询各人未收本金与结算账户")
        latest = client.get_receivable(rid)
        print(
            "unrecovered holdings:",
            {h["account_id"]: h["held_cents"] for h in latest["holdings"]},
            "remaining:",
            latest["remaining_cents"],
        )
        accounts_view = client.settlement_accounts()
        summary = [
            {
                "account_id": row["account_id"],
                "available_cents": row["available_cents"],
                "pending_deduction_cents": row["pending_deduction_cents"],
                "total_allocated_cents": row["total_allocated_cents"],
                "total_clawback_cents": row["total_clawback_cents"],
                "total_disbursed_cents": row["total_disbursed_cents"],
            }
            for row in accounts_view["accounts"]
        ]
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        write_json(workdir / "settlement-accounts.json", accounts_view)
        write_json(workdir / "receivable.json", latest)

        print("\n演示完成。产物目录:", workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
