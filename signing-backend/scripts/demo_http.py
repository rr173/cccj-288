#!/usr/bin/env python3
"""End-to-end HTTP demonstration.

It starts from an empty server/database and demonstrates:
  1. two stages with parallel signing inside each eligible stage;
  2. continuous delegation, cycle rejection, initiator revocation, and the
     fact that old challenges do not become valid after delegating back;
  3. same operation-ID replay and one-challenge/one-signature enforcement;
  4. offline certificate verification.

The server must already be running. Use ../run_demo.sh to start it safely.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from client_lib import ApiCallError, KeyStore, SigningClient, operation_id  # noqa: E402
from signing_backend.verifier import format_text_report, verify_certificate  # noqa: E402


def heading(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def expect_api_code(expected_code: str, func: Callable[[], Any], context: str) -> None:
    try:
        func()
    except ApiCallError as exc:
        if exc.code != expected_code:
            raise AssertionError(
                f"{context}: expected {expected_code}, got {exc.code}: {exc.body}"
            ) from exc
        print(f"[预期拒绝] {context}: {exc.code}")
        return
    raise AssertionError(f"{context}: expected API error {expected_code}, but call succeeded")


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def parallel_sign(
    base_url: str,
    agreement_id: str,
    seat_id: str,
    keys_dir: Path,
    account: str,
    run_id: str,
) -> dict[str, Any]:
    # Each worker gets its own httpx client; the private key is read locally.
    store = KeyStore(keys_dir)
    signer = store.load(account)
    with SigningClient(base_url) as client:
        return client.sign_challenge(
            agreement_id,
            seat_id,
            signer,
            challenge_op=f"challenge-{account}-{run_id}",
            signature_op=f"signature-{account}-{run_id}",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    keys_dir = workdir / "keys"
    run_id = uuid.uuid4().hex[:10]

    store = KeyStore(keys_dir)
    accounts = ["alice", "bob", "carol", "dave", "owner", "delegate_a", "delegate_b", "cancel_user"]
    signers = {name: store.load_or_create(name) for name in accounts}

    with SigningClient(args.base_url) as client:
        heading("0. 健康检查并登记本机 Ed25519 公钥（私钥不离开脚本）")
        print(client.health())
        for name in accounts:
            result = client.register(signers[name], op_id=f"register-{name}-{run_id}")
            print(f"registered {name}: {result['public_key_b64'][:24]}...")
        registry = client.accounts()
        write_json(workdir / "registry.json", registry)

        # -----------------------------------------------------------------
        heading("1. 创建两阶段协议；发送后正文与席位冻结")
        body_text = (
            "多方共同确认协议正文\n"
            f"演示运行编号: {run_id}\n"
            "第一条：所有签署人确认本正文。\n"
            "第二条：第一阶段席位完成后，第二阶段方可签署；同阶段可并行。\n"
            "第三条：委托、撤销、挑战和签署均由后端按当前状态裁决。\n"
        )
        body_path = workdir / "agreement-body.txt"
        body_path.write_text(body_text, encoding="utf-8")

        seats = [
            {"seat_key": "stage1-alice", "label": "第一阶段·甲方", "original_account_id": "alice", "stage": 1},
            {"seat_key": "stage1-bob", "label": "第一阶段·乙方", "original_account_id": "bob", "stage": 1},
            {"seat_key": "stage2-carol", "label": "第二阶段·复核人", "original_account_id": "carol", "stage": 2},
            {"seat_key": "stage2-dave", "label": "第二阶段·批准人", "original_account_id": "dave", "stage": 2},
        ]
        agreement = client.create_agreement(
            initiator="initiator-1",
            title="两阶段并行签署演示协议",
            content_text=body_text,
            seats=seats,
            op_id=f"create-two-stage-{run_id}",
        )
        aid = agreement["agreement_id"]
        print("draft agreement:", aid)
        sent = client.send(aid, "initiator-1", op_id=f"send-{aid}-{run_id}")
        print("status after send:", sent["status"], "body hash:", sent["content_sha256"])

        by_key = {seat["seat_key"]: seat for seat in sent["seats"]}

        heading("2. 前一阶段未全部完成时，第二阶段挑战被拒绝")
        expect_api_code(
            "STAGE_LOCKED",
            lambda: client.issue_challenge(
                aid, by_key["stage2-carol"]["seat_id"], "carol", f"early-challenge-{run_id}"
            ),
            "Carol 在第一阶段未完成时请求挑战",
        )

        heading("3. 第一阶段两个席位并行签署")
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_alice = pool.submit(
                parallel_sign, args.base_url, aid, by_key["stage1-alice"]["seat_id"],
                keys_dir, "alice", run_id + "-s1a",
            )
            f_bob = pool.submit(
                parallel_sign, args.base_url, aid, by_key["stage1-bob"]["seat_id"],
                keys_dir, "bob", run_id + "-s1b",
            )
            r_alice = f_alice.result()
            r_bob = f_bob.result()
        print("alice:", r_alice["signature_id"], r_alice["agreement_status"])
        print("bob:  ", r_bob["signature_id"], r_bob["agreement_status"])

        after_stage1 = client.get_agreement(aid)
        print("signed_count:", after_stage1["signed_count"], "/", after_stage1["seat_count"])

        heading("4. 第二阶段两个席位并行签署并生成凭证")
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_carol = pool.submit(
                parallel_sign, args.base_url, aid, by_key["stage2-carol"]["seat_id"],
                keys_dir, "carol", run_id + "-s2c",
            )
            f_dave = pool.submit(
                parallel_sign, args.base_url, aid, by_key["stage2-dave"]["seat_id"],
                keys_dir, "dave", run_id + "-s2d",
            )
            r_carol = f_carol.result()
            r_dave = f_dave.result()
        print("carol:", r_carol["signature_id"], r_carol["agreement_status"])
        print("dave: ", r_dave["signature_id"], r_dave["agreement_status"])

        certificate = client.certificate(aid)
        cert_path = workdir / "two-stage-certificate.json"
        write_json(cert_path, certificate)
        print("certificate saved:", cert_path)

        report = verify_certificate(certificate, registry=registry)
        print(format_text_report(report))
        if not report["valid"]:
            raise AssertionError(f"two-stage certificate invalid: {report['errors']}")

        # -----------------------------------------------------------------
        heading("5. 连续委托：owner -> delegate_a -> delegate_b")
        body2 = f"委托链演示协议 {run_id}\n本协议用于连续委托、撤销和旧挑战重放。\n"
        agreement2 = client.create_agreement(
            initiator="initiator-2",
            title="委托链与撤销演示协议",
            content_text=body2,
            seats=[
                {"seat_key": "delegated-seat", "original_account_id": "owner", "stage": 1}
            ],
            op_id=f"create-delegation-{run_id}",
        )
        aid2 = agreement2["agreement_id"]
        client.send(aid2, "initiator-2", op_id=f"send-{aid2}-{run_id}")
        seat2 = client.get_agreement(aid2)["seats"][0]
        sid2 = seat2["seat_id"]

        d1 = client.delegate(aid2, sid2, "owner", "delegate_a", f"del-owner-a-{run_id}")
        print("owner -> delegate_a:", d1["delegation_id"])

        # Obtain A's challenge while A is still the current authority. It is
        # intentionally not submitted until after later delegation/revocation.
        old_a_challenge = client.issue_challenge(
            aid2, sid2, "delegate_a", f"old-a-challenge-{run_id}"
        )
        old_a_challenge_id = old_a_challenge.headers["x-challenge-id"]
        old_a_signature = signers["delegate_a"].sign_exact_bytes(old_a_challenge.content)
        print("saved old A challenge before A delegates onward:", old_a_challenge_id)

        d2 = client.delegate(aid2, sid2, "delegate_a", "delegate_b", f"del-a-b-{run_id}")
        print("delegate_a -> delegate_b:", d2["delegation_id"])

        heading("6. 环和越权委托必须被拒绝")
        expect_api_code(
            "DELEGATION_CYCLE",
            lambda: client.delegate(aid2, sid2, "delegate_b", "owner", f"cycle-owner-{run_id}"),
            "delegate_b 试图委托回 owner",
        )
        expect_api_code(
            "DELEGATION_CYCLE",
            lambda: client.delegate(aid2, sid2, "delegate_b", "delegate_a", f"cycle-a-{run_id}"),
            "delegate_b 试图委托回 delegate_a",
        )
        expect_api_code(
            "NOT_CURRENT_AUTHORITY",
            lambda: client.delegate(aid2, sid2, "delegate_a", "cancel_user", f"unauth-{run_id}"),
            "已继续委托的 delegate_a 试图再次委托",
        )

        heading("7. B 在成为当前被授权人后取得挑战并在本地签名")
        # B obtains a challenge after A -> B.
        old_b_challenge = client.issue_challenge(
            aid2, sid2, "delegate_b", f"old-b-challenge-{run_id}"
        )
        old_b_challenge_id = old_b_challenge.headers["x-challenge-id"]
        old_b_signature = signers["delegate_b"].sign_exact_bytes(old_b_challenge.content)
        print("saved old B challenge:", old_b_challenge_id)

        heading("8. 发起人撤销整条链，再委托回 A；旧挑战仍永久失效")
        revocation = client.revoke(aid2, sid2, "initiator-2", f"revoke-{run_id}")
        print("revoked chain length:", len(revocation["revoked_chain"]), "authority returns to owner")
        client.delegate(aid2, sid2, "owner", "delegate_a", f"redelegate-a-{run_id}")
        print("owner -> delegate_a again; authority generation changed")

        expect_api_code(
            "AUTHORITY_STALE",
            lambda: client.submit_signature(
                old_a_challenge_id, old_a_signature, f"replay-old-a-{run_id}"
            ),
            "委托回同一 A 后重放 A 的旧挑战",
        )
        expect_api_code(
            "AUTHORITY_STALE",
            lambda: client.submit_signature(
                old_b_challenge_id, old_b_signature, f"replay-old-b-{run_id}"
            ),
            "撤销后重放 B 的旧挑战",
        )

        heading("9. A 用新挑战签署；相同操作 ID 重试返回首次结果，换操作 ID 不能产生第二事实")
        new_challenge = client.issue_challenge(
            aid2, sid2, "delegate_a", f"new-a-challenge-{run_id}"
        )
        new_challenge_id = new_challenge.headers["x-challenge-id"]
        new_signature = signers["delegate_a"].sign_exact_bytes(new_challenge.content)
        sign_op = f"new-a-sign-{run_id}"
        first_sign = client.submit_signature(new_challenge_id, new_signature, sign_op)
        retry_same_op = client.submit_signature(new_challenge_id, new_signature, sign_op)
        assert first_sign["signature_id"] == retry_same_op["signature_id"]
        print("first signature:", first_sign["signature_id"])
        print("same operation retry returns same signature_id:", retry_same_op["signature_id"])

        expect_api_code(
            "CHALLENGE_ALREADY_USED",
            lambda: client.submit_signature(
                new_challenge_id, new_signature, f"different-op-replay-{run_id}"
            ),
            "用新操作 ID 重放同一已消费挑战",
        )

        delegation_cert = client.certificate(aid2)
        delegation_cert_path = workdir / "delegation-certificate.json"
        write_json(delegation_cert_path, delegation_cert)
        delegation_report = verify_certificate(delegation_cert, registry=registry)
        if not delegation_report["valid"]:
            raise AssertionError(f"delegation certificate invalid: {delegation_report['errors']}")
        print("delegation certificate verified:", delegation_cert_path)
        for seat_report in delegation_report["seats"]:
            print("actual signer:", seat_report["actual_signer_account_id"])
            print("authority path:", " -> ".join(seat_report["delegation"]["authority_path"]))

        # -----------------------------------------------------------------
        heading("10. 发起人可取消未完成协议（并发最后签名竞争由 pytest 覆盖）")
        agreement3 = client.create_agreement(
            initiator="initiator-3",
            title="取消演示协议",
            content_text=f"取消演示 {run_id}\n",
            seats=[{"seat_key": "only", "original_account_id": "cancel_user", "stage": 1}],
            op_id=f"create-cancel-{run_id}",
        )
        aid3 = agreement3["agreement_id"]
        client.send(aid3, "initiator-3", op_id=f"send3-{run_id}")
        cancelled = client.cancel(
            aid3, "initiator-3", "demo cancellation", op_id=f"cancel-{run_id}"
        )
        print("agreement status:", cancelled["status"])
        cancel_seat = cancelled["seats"][0]
        expect_api_code(
            "AGREEMENT_NOT_ACTIVE",
            lambda: client.issue_challenge(
                aid3, cancel_seat["seat_id"], "cancel_user", f"challenge-after-cancel-{run_id}"
            ),
            "取消后请求签署挑战",
        )

        heading("演示完成")
        print("Artifacts in:", workdir)
        print(" -", cert_path)
        print(" -", delegation_cert_path)
        print(" -", workdir / "registry.json")
        print(" -", body_path)
        print("\n独立验签命令：")
        print(
            f"python verify_certificate.py {cert_path} "
            f"--registry {workdir / 'registry.json'} --body-file {body_path}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
