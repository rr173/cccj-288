#!/usr/bin/env python3
"""Convenience wrapper: python verify_certificate.py cert.json --registry accounts.json."""

from signing_backend.verifier import main

if __name__ == "__main__":
    raise SystemExit(main())
