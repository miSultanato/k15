#!/usr/bin/env python3
"""Deterministic P-256 nonce boundary checks against the frozen reference signer.

Usage: test_ecdsa_nonce_boundaries.py TARGET
This imports only TARGET/tools/ec.py and uses a synthetic private scalar.
"""
from __future__ import annotations

import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

if len(sys.argv) != 2:
    raise SystemExit("usage: test_ecdsa_nonce_boundaries.py TARGET")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
import ec as reference  # noqa: E402

n = reference.N256
d = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234
z = 0xA5A5A5A55A5A5A5A0123456789ABCDEF00112233445566778899AABBCCDDEEFF
key = ec.derive_private_key(d, ec.SECP256R1())
public_key = key.public_key()
machine = reference.Machine()
table = machine.table256()


def sign(k: int) -> tuple[int, int]:
    return machine.sign(table, d, k, z)


def verify(signature: tuple[int, int]) -> bool:
    r, s = signature
    if not (0 < r < n and 0 < s < n):
        return False
    try:
        public_key.verify(
            utils.encode_dss_signature(r, s),
            z.to_bytes(32, "big"),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


sig_one = sign(1)
sig_n_plus_one = sign(n + 1)
if not verify(sig_one):
    raise SystemExit("FAIL: control nonce k=1 did not verify")
if not verify(sig_n_plus_one):
    raise SystemExit("FAIL: nonce k=n+1 did not produce a valid P-256 signature")
if sig_n_plus_one != sig_one:
    raise SystemExit("FAIL: k=n+1 did not behave identically to effective nonce k=1")
print("PASS: k=n+1 aliases k=1 in the frozen Python reference signer")

sig_n_minus_one = sign(n - 1)
if not verify(sig_n_minus_one):
    raise SystemExit("FAIL: k=n-1 did not produce a valid P-256 signature")
print("PASS: k=n-1 produces a valid, deterministic signature")

sig_n = sign(n)
if verify(sig_n):
    raise SystemExit("FAIL: k=n (zero modulo n) unexpectedly verified")
print("PASS: k=n does not produce a valid signature")

print("RESULT: deterministic P-256 reference boundary checks passed")
