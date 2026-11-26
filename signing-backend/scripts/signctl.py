#!/usr/bin/env python3
"""Runnable local Ed25519 key and signing CLI.

Examples:
  python scripts/signctl.py keygen --keys-dir ./keys --account alice
  python scripts/signctl.py register --base-url http://127.0.0.1:18080 \
      --keys-dir ./keys --account alice
  python scripts/signctl.py sign-challenge --base-url http://127.0.0.1:18080 \
      --keys-dir ./keys --agreement agr_... --seat seat_... --account alice
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from client_lib import ApiCallError, KeyStore, SigningClient, operation_id  # noqa: E402
from signing_backend.verifier import load_registry, verify_certificate  # noqa: E402


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def cmd_keygen(args: argparse.Namespace) -> int:
    store = KeyStore(args.keys_dir)
    for account in args.account:
        signer = store.load_or_create(account)
        print(f"{account}: public_key_b64={signer.public_key_b64}")
        print(f"  private key stays at {store._private_path(account)}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    store = KeyStore(args.keys_dir)
    with SigningClient(args.base_url) as client:
        for account in args.account:
            signer = store.load_or_create(account)
            result = client.register(signer, op_id=f"register-{account}-v1")
            _print_json(result)
    return 0


def cmd_sign_challenge(args: argparse.Namespace) -> int:
    store = KeyStore(args.keys_dir)
    signer = store.load(args.account)
    with SigningClient(args.base_url) as client:
        result = client.sign_challenge(
            args.agreement,
            args.seat,
            signer,
            challenge_op=args.challenge_operation_id,
            signature_op=args.signature_operation_id or args.operation_id,
        )
        _print_json(result)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    certificate = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
    registry = load_registry(args.registry) if args.registry else None
    report = verify_certificate(certificate, registry=registry)
    body = report.pop("body_bytes", None)
    if args.write_body and body is not None and report["valid"]:
        Path(args.write_body).write_bytes(body)
    _print_json(report)
    return 0 if report["valid"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local Ed25519 signing control script.")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate or load local Ed25519 keys")
    keygen.add_argument("--keys-dir", required=True)
    keygen.add_argument("--account", action="append", required=True)
    keygen.set_defaults(func=cmd_keygen)

    register = sub.add_parser("register", help="Register only the public key with the server")
    register.add_argument("--keys-dir", required=True)
    register.add_argument("--account", action="append", required=True)
    register.set_defaults(func=cmd_register)

    sign = sub.add_parser("sign-challenge", help="Fetch raw challenge bytes and sign them locally")
    sign.add_argument("--keys-dir", required=True)
    sign.add_argument("--agreement", required=True)
    sign.add_argument("--seat", required=True)
    sign.add_argument("--account", required=True)
    sign.add_argument("--operation-id", help="Idempotency operation ID for signature submission")
    sign.add_argument("--challenge-operation-id")
    sign.add_argument("--signature-operation-id")
    sign.set_defaults(func=cmd_sign_challenge)

    verify = sub.add_parser("verify", help="Verify a certificate offline")
    verify.add_argument("certificate")
    verify.add_argument("--registry")
    verify.add_argument("--write-body")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ApiCallError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if isinstance(exc.body, (dict, list)):
            print(json.dumps(exc.body, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
