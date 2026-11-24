#!/usr/bin/env python3
"""Unit tests for the public-tree hygiene guard; uses marker strings only."""
from __future__ import annotations

from check_public_hygiene import PEM_BEGIN, PRIVATE_KEY, forbidden_path


def main() -> None:
    markers = [
        PEM_BEGIN + b"PRIVATE KEY-----",
        PEM_BEGIN + b"RSA PRIVATE KEY-----",
        PEM_BEGIN + b"EC PRIVATE KEY-----",
        PEM_BEGIN + b"DSA PRIVATE KEY-----",
        PEM_BEGIN + b"OPENSSH PRIVATE KEY-----",
        PEM_BEGIN + b"ENCRYPTED PRIVATE KEY-----",
    ]
    for marker in markers:
        if not PRIVATE_KEY.search(marker):
            raise SystemExit(f"FAIL: private-key marker was not detected: {marker!r}")
    if PRIVATE_KEY.search(PEM_BEGIN + b"CERTIFICATE-----"):
        raise SystemExit("FAIL: public certificate marker was treated as a private key")

    blocked = (
        "cert/server.key",
        "cert-15kb.org/server.key",
        "nested/cert-15kb.org/bounty-server.pem",
        "build/os.bin",
        "build-example.org/disk.img",
        "audit/regs.inc",
        "cert/server.p12",
        "build/os.lst",
    )
    for path in blocked:
        if not forbidden_path(path):
            raise SystemExit(f"FAIL: generated/private path was not blocked: {path}")

    allowed = (
        "bench/build-nginx-boring.sh",
        "audit/check_public_hygiene.py",
        "src/os.asm",
        "README.md",
    )
    for path in allowed:
        if forbidden_path(path):
            raise SystemExit(f"FAIL: legitimate public source was blocked: {path}")

    print("PASS: private-key marker variants, artifact paths and safe source paths")


if __name__ == "__main__":
    main()
