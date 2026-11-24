#!/usr/bin/env python3
"""Unit tests for the public-tree hygiene guard; uses marker strings only."""
from __future__ import annotations

from check_public_hygiene import PRIVATE_KEY, forbidden_path


def main() -> None:
    labels = (
        b"PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"DSA PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
    )
    for label in labels:
        block = (
            b"-----BEGIN " + label + b"-----\n"
            + b"QUJDREVGR0hJSktMTU5PUA==\n"
            + b"-----END " + label + b"-----"
        )
        if not PRIVATE_KEY.search(block):
            raise SystemExit(f"FAIL: complete PEM block was not detected: {label!r}")
        if PRIVATE_KEY.search(b"-----BEGIN " + label + b"-----"):
            raise SystemExit("FAIL: header-only marker was treated as a private key")
    public_cert = (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"QUJDREVGR0hJSktMTU5PUA==\n"
        + b"-----END CERTIFICATE-----"
    )
    if PRIVATE_KEY.search(public_cert):
        raise SystemExit("FAIL: public certificate block was treated as a private key")

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

    print("PASS: complete private-key PEM blocks, artifact paths and safe source paths")


if __name__ == "__main__":
    main()
