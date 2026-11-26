"""Offline certificate verifier.

This module deliberately depends only on the certificate JSON, an optional
trusted account/public-key registry, and the cryptography library.  It does not
connect to the server or read SQLite.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature

from .security import (
    b64d,
    canonical_json_bytes,
    sha256_id,
    verify_ed25519_b64,
)


def coerce_registry(registry: Optional[dict[str, Any]]) -> Optional[dict[str, str]]:
    if registry is None:
        return None
    if isinstance(registry.get("public_keys"), dict):
        return dict(registry["public_keys"])
    if isinstance(registry.get("accounts"), list):
        return {row["account_id"]: row["public_key_b64"] for row in registry["accounts"]}
    return dict(registry)


def load_registry(path: str | Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("public_keys"), dict):
        return dict(data["public_keys"])
    if isinstance(data, dict) and isinstance(data.get("accounts"), list):
        return {row["account_id"]: row["public_key_b64"] for row in data["accounts"]}
    if isinstance(data, dict):
        result: dict[str, str] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = value
            elif isinstance(value, dict) and isinstance(value.get("public_key_b64"), str):
                result[key] = value["public_key_b64"]
        return result
    raise ValueError("Unsupported registry JSON format")


def _err(errors: list[str], message: str) -> None:
    errors.append(message)


def _verify_delegation(
    errors: list[str],
    seat_label: str,
    seat: dict[str, Any],
    signature: dict[str, Any],
    challenge: dict[str, Any],
    registry: Optional[dict[str, str]],
) -> Optional[dict[str, Any]]:
    source = signature.get("delegation_source")
    if not isinstance(source, dict):
        _err(errors, f"{seat_label}: missing delegation_source")
        return None

    if challenge.get("authority_hash") != sha256_id(
        canonical_json_bytes(challenge.get("authority"))
    ):
        _err(errors, f"{seat_label}: challenge authority hash does not match bound authority object")

    original = seat.get("original_account_id")
    actual = signature.get("actual_signer_account_id")
    chain = source.get("active_chain")
    if not isinstance(chain, list):
        _err(errors, f"{seat_label}: delegation_source.active_chain must be a list")
        return None

    if source.get("original_account_id") != original:
        _err(errors, f"{seat_label}: delegation source original account mismatch")
    if source.get("current_account_id") != actual:
        _err(errors, f"{seat_label}: delegation source current/actual account mismatch")
    if signature.get("authority_generation") != source.get("authority_generation"):
        _err(errors, f"{seat_label}: authority generation mismatch in delegation source")
    if challenge.get("authority_hash") != sha256_id(canonical_json_bytes(source)):
        _err(errors, f"{seat_label}: challenge authority_hash does not match delegation source")

    path = [original]
    for index, link in enumerate(chain, start=1):
        if not isinstance(link, dict):
            _err(errors, f"{seat_label}: delegation chain link {index} is not an object")
            continue
        if link.get("seq") != index:
            _err(errors, f"{seat_label}: delegation chain link {index} has non-sequential seq")
        expected_delegator = path[-1]
        if link.get("delegator_account_id") != expected_delegator:
            _err(
                errors,
                f"{seat_label}: delegation chain breaks at link {index}: "
                f"expected delegator {expected_delegator!r}",
            )
        delegatee = link.get("delegatee_account_id")
        if delegatee in path:
            _err(errors, f"{seat_label}: delegation cycle detected involving {delegatee!r}")
        path.append(delegatee)

    basis = source.get("authority_basis")
    if not chain:
        if basis != "ORIGINAL":
            _err(errors, f"{seat_label}: empty chain must have ORIGINAL basis")
        if actual != original:
            _err(errors, f"{seat_label}: original seat was not signed by original account")
    else:
        if basis != "DELEGATION":
            _err(errors, f"{seat_label}: non-empty chain must have DELEGATION basis")
        if path[-1] != actual:
            _err(
                errors,
                f"{seat_label}: chain terminal {path[-1]!r} does not match actual signer {actual!r}",
            )

    if registry is not None:
        accounts_to_check = set(path)
        for account_id in accounts_to_check:
            if account_id not in registry:
                _err(errors, f"{seat_label}: account {account_id!r} absent from trusted registry")
        expected_key = registry.get(actual)
        if expected_key is not None and expected_key != signature.get("signer_public_key_b64"):
            _err(errors, f"{seat_label}: signer public key is not the registry key for {actual!r}")

    return {
        "original_account_id": original,
        "actual_signer_account_id": actual,
        "authority_basis": basis,
        "authority_path": path,
        "delegation_count": len(chain),
        "authority_generation": signature.get("authority_generation"),
    }


def verify_certificate(
    certificate: dict[str, Any],
    registry: Optional[dict[str, str]] = None,
    expected_body: Optional[bytes] = None,
) -> dict[str, Any]:
    registry = coerce_registry(registry)
    errors: list[str] = []
    warnings: list[str] = []
    seat_reports: list[dict[str, Any]] = []

    if certificate.get("schema") != "multi-party-agreement-signed-certificate/v1":
        _err(errors, "Unsupported certificate schema")

    supplied_hash = certificate.get("certificate_hash")
    core = {key: value for key, value in certificate.items() if key != "certificate_hash"}
    actual_certificate_hash = sha256_id(canonical_json_bytes(core))
    if supplied_hash != actual_certificate_hash:
        _err(errors, "certificate_hash mismatch: certificate contents were tampered with or hash is absent")

    body = certificate.get("body")
    body_bytes: Optional[bytes] = None
    if not isinstance(body, dict):
        _err(errors, "certificate has no body object")
    else:
        try:
            body_bytes = b64d(body.get("data", ""))
        except Exception:
            _err(errors, "body.data is not valid base64")
        if body_bytes is not None:
            if body.get("sha256") != sha256_id(body_bytes):
                _err(errors, "body sha256 does not match embedded body bytes")
            if body.get("byte_length") != len(body_bytes):
                _err(errors, "body byte_length does not match embedded body")
            if expected_body is not None and body_bytes != expected_body:
                _err(errors, "supplied --body-file bytes do not exactly match certificate body")

    seats = certificate.get("seats")
    seats = seats if isinstance(seats, list) else []
    if not seats:
        _err(errors, "certificate contains no seats")

    seat_ids: set[str] = set()
    signature_ids: set[str] = set()
    challenge_ids: set[str] = set()

    for index, seat in enumerate(seats, start=1):
        if not isinstance(seat, dict):
            _err(errors, f"seat {index}: not an object")
            continue
        seat_label = f"seat {seat.get('seat_key') or seat.get('seat_id') or index}"
        seat_id = seat.get("seat_id")
        if seat_id in seat_ids:
            _err(errors, f"{seat_label}: duplicate seat_id")
        seat_ids.add(seat_id)

        if seat.get("status") != "signed":
            _err(errors, f"{seat_label}: seat status is {seat.get('status')!r}, not 'signed'")

        signature = seat.get("signature")
        if not isinstance(signature, dict):
            _err(errors, f"{seat_label}: missing signature object")
            continue

        sig_id = signature.get("signature_id")
        chal_id = signature.get("challenge_id")
        if sig_id in signature_ids:
            _err(errors, f"{seat_label}: duplicate signature_id")
        signature_ids.add(sig_id)
        if chal_id in challenge_ids:
            _err(errors, f"{seat_label}: challenge_id reused by multiple seats")
        challenge_ids.add(chal_id)

        try:
            challenge_bytes = b64d(signature.get("challenge_b64", ""))
            challenge = json.loads(challenge_bytes.decode("utf-8"))
            if not isinstance(challenge, dict):
                raise ValueError("challenge is not a JSON object")
        except Exception as exc:
            _err(errors, f"{seat_label}: challenge_b64 is invalid: {exc}")
            continue

        if challenge.get("challenge_id") != chal_id:
            _err(errors, f"{seat_label}: challenge ID mismatch")
        if challenge.get("agreement_id") != certificate.get("agreement_id"):
            _err(errors, f"{seat_label}: challenge agreement_id mismatch")
        if challenge.get("seat", {}).get("seat_id") != seat_id:
            _err(errors, f"{seat_label}: challenge seat_id mismatch")
        if challenge.get("seat", {}).get("stage") != seat.get("stage"):
            _err(errors, f"{seat_label}: challenge stage mismatch")
        if challenge.get("seat", {}).get("original_account_id") != seat.get("original_account_id"):
            _err(errors, f"{seat_label}: challenge original account mismatch")
        if challenge.get("body_sha256") != body.get("sha256"):
            _err(errors, f"{seat_label}: challenge body hash does not match certificate body")
        if signature.get("body_sha256") != body.get("sha256"):
            _err(errors, f"{seat_label}: signature body hash does not match certificate body")

        actual = signature.get("actual_signer_account_id")
        public_key_b64 = signature.get("signer_public_key_b64")
        if challenge.get("signer", {}).get("account_id") != actual:
            _err(errors, f"{seat_label}: challenge signer account mismatch")
        if challenge.get("signer", {}).get("public_key_b64") != public_key_b64:
            _err(errors, f"{seat_label}: challenge signer public key mismatch")

        try:
            verify_ed25519_b64(public_key_b64, challenge_bytes, signature.get("signature_b64", ""))
            signature_valid = True
        except InvalidSignature:
            signature_valid = False
            _err(errors, f"{seat_label}: INVALID ED25519 SIGNATURE over exact challenge bytes")
        except Exception as exc:
            signature_valid = False
            _err(errors, f"{seat_label}: malformed key/signature: {exc}")

        delegation_report = _verify_delegation(
            errors, seat_label, seat, signature, challenge, registry
        )

        gate = signature.get("stage_gate")
        if gate != challenge.get("stage_gate"):
            _err(errors, f"{seat_label}: signature stage_gate does not match challenge stage_gate")
        if not isinstance(gate, dict) or not gate.get("all_lower_stages_completed"):
            _err(errors, f"{seat_label}: stage gate does not show all lower stages complete")
        else:
            expected_lower_signature_ids = [
                other.get("signature", {}).get("signature_id")
                for other in seats
                if isinstance(other, dict)
                and isinstance(other.get("stage"), int)
                and other["stage"] < seat.get("stage", 0)
            ]
            actual_lower_ids = gate.get("completed_lower_stage_signature_ids", [])
            if set(actual_lower_ids) != set(expected_lower_signature_ids):
                _err(errors, f"{seat_label}: stage gate lower-stage signature set does not match certificate")

        if registry is None:
            warnings.append(
                "No --registry supplied: Ed25519 keys and delegation chain are verified, "
                "but account-to-public-key binding is not anchored to a trusted registry."
            )

        seat_reports.append(
            {
                "seat_id": seat_id,
                "seat_key": seat.get("seat_key"),
                "stage": seat.get("stage"),
                "status": seat.get("status"),
                "original_account_id": seat.get("original_account_id"),
                "actual_signer_account_id": actual,
                "signed_at": seat.get("completed_at"),
                "signature_valid": signature_valid,
                "delegation": delegation_report,
            }
        )

    # Verify stage summary counts.
    summary = certificate.get("stage_summary")
    expected_summary: dict[int, dict[str, int]] = {}
    for seat in seats:
        stage = seat.get("stage") if isinstance(seat, dict) else None
        if not isinstance(stage, int):
            continue
        item = expected_summary.setdefault(stage, {"seat_count": 0, "signed_count": 0})
        item["seat_count"] += 1
        if seat.get("status") == "signed":
            item["signed_count"] += 1
    if not isinstance(summary, list):
        _err(errors, "stage_summary is missing or not a list")
    else:
        actual_summary = {
            row.get("stage"): {
                "seat_count": row.get("seat_count"),
                "signed_count": row.get("signed_count"),
            }
            for row in summary
            if isinstance(row, dict)
        }
        if actual_summary != expected_summary:
            _err(errors, "stage_summary does not match seat completion records")

    return {
        "valid": not errors,
        "agreement_id": certificate.get("agreement_id"),
        "certificate_id": certificate.get("certificate_id"),
        "title": certificate.get("title"),
        "body_sha256": body.get("sha256") if isinstance(body, dict) else None,
        "body_byte_length": len(body_bytes) if body_bytes is not None else None,
        "certificate_hash_valid": supplied_hash == actual_certificate_hash,
        "registry_used": registry is not None,
        "errors": errors,
        "warnings": sorted(set(warnings)),
        "seats": seat_reports,
        "body_bytes": body_bytes,
    }


def format_text_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("独立签署凭证核验")
    lines.append("=" * 78)
    lines.append(f"协议 ID:       {report.get('agreement_id')}")
    lines.append(f"凭证 ID:       {report.get('certificate_id')}")
    lines.append(f"标题:          {report.get('title')}")
    lines.append(f"正文哈希:      {report.get('body_sha256')}")
    lines.append(f"正文字节数:    {report.get('body_byte_length')}")
    lines.append(f"凭证哈希正确:  {report.get('certificate_hash_valid')}")
    lines.append(f"可信注册表:    {'是' if report.get('registry_used') else '否（仅凭证内密钥自洽）'}")
    lines.append("")
    lines.append("席位完成情况 / 实际签署人:")
    for seat in report.get("seats", []):
        delegation = seat.get("delegation") or {}
        path = " -> ".join(delegation.get("authority_path") or [])
        lines.append(
            f"  - 阶段 {seat.get('stage')} {seat.get('seat_key')} "
            f"[{seat.get('status')}] 原责任人={seat.get('original_account_id')} "
            f"实际签署={seat.get('actual_signer_account_id')} "
            f"签名={'OK' if seat.get('signature_valid') else 'BAD'}"
        )
        if delegation.get("delegation_count"):
            lines.append(f"      委托来源: {path}")
        else:
            lines.append("      委托来源: 原责任人直接签署")
        lines.append(f"      签署时间: {seat.get('signed_at')}")

    if report.get("warnings"):
        lines.append("")
        lines.append("警告:")
        for warning in report["warnings"]:
            lines.append(f"  ! {warning}")
    if report.get("errors"):
        lines.append("")
        lines.append("错误:")
        for error in report["errors"]:
            lines.append(f"  X {error}")
        lines.append("")
        lines.append("结论: 核验失败")
    else:
        lines.append("")
        lines.append("结论: 凭证、正文、Ed25519 签名、委托链和阶段完成情况全部核验通过 ✅")
    lines.append("=" * 78)
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Independently verify a signing certificate.")
    parser.add_argument("certificate", help="Path to certificate JSON")
    parser.add_argument("--registry", help="Trusted accounts/public-keys JSON exported from /accounts")
    parser.add_argument("--body-file", help="Optional original body file to compare byte-for-byte")
    parser.add_argument("--write-body", help="Write verified embedded body bytes to this path")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON report")
    args = parser.parse_args(argv)

    certificate = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
    registry = load_registry(args.registry) if args.registry else None
    expected_body = Path(args.body_file).read_bytes() if args.body_file else None

    report = verify_certificate(certificate, registry=registry, expected_body=expected_body)
    body_bytes = report.pop("body_bytes", None)
    if args.write_body and body_bytes is not None and report["valid"]:
        Path(args.write_body).write_bytes(body_bytes)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_text_report(report))
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    sys.exit(main())
