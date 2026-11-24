#!/usr/bin/env python3
"""Deterministic P-256 nonce boundary checks against the frozen assembly signer.

Usage: test_ecdsa_nonce_boundaries.py TARGET
Requires TARGET/build/test_asm, built by `make test`. Uses synthetic key material.
"""
from __future__ import annotations

import subprocess
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
R = reference.R
d = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234
z = 0xA5A5A5A55A5A5A5A0123456789ABCDEF00112233445566778899AABBCCDDEEFF
key = ec.derive_private_key(d, ec.SECP256R1())
public_key = key.public_key()
d_mont = d * R % n

# test_asm's command protocol takes D and K little-endian, Z big-endian;
# D is the Montgomery-form private scalar used by the assembly signer.
cases = (("k=1", 1), ("k=n-1", n - 1), ("k=n", n), ("k=n+1", n + 1))
commands = "".join(
    f"sign {d_mont.to_bytes(32, 'little').hex()} "
    f"{k.to_bytes(32, 'little').hex()} {z.to_bytes(32, 'big').hex()}\n"
    for _, k in cases
)
binary = target / "build" / "test_asm"
result = subprocess.run(
    [str(binary), "commands"],
    input=commands,
    capture_output=True,
    text=True,
    check=True,
)
outputs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
if len(outputs) != len(cases):
    raise SystemExit(
        f"FAIL: expected {len(cases)} assembly signatures, got {len(outputs)}; "
        f"stderr={result.stderr.strip()}"
    )


def decode(raw: str) -> tuple[int, int]:
    data = bytes.fromhex(raw)
    if len(data) != 64:
        raise SystemExit(f"FAIL: assembly returned {len(data)} bytes, expected 64")
    return int.from_bytes(data[:32], "little"), int.from_bytes(data[32:], "little")


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


signatures = {label: decode(raw) for (label, _), raw in zip(cases, outputs)}
if not verify(signatures["k=1"]):
    raise SystemExit("FAIL: assembly control nonce k=1 did not verify")
if not verify(signatures["k=n-1"]):
    raise SystemExit("FAIL: assembly nonce k=n-1 did not verify")
if not verify(signatures["k=n+1"]):
    raise SystemExit("FAIL: assembly nonce k=n+1 did not verify")
if signatures["k=n+1"] != signatures["k=1"]:
    raise SystemExit("FAIL: assembly k=n+1 did not alias effective nonce k=1")
if verify(signatures["k=n"]):
    raise SystemExit("FAIL: assembly nonce k=n (zero modulo n) unexpectedly verified")

print("PASS: assembly k=n+1 aliases k=1; both signatures verify")
print("PASS: assembly k=n-1 produces a valid P-256 signature")
print("PASS: assembly k=n (zero modulo n) does not produce a valid signature")
print("RESULT: deterministic P-256 assembly nonce boundary checks passed")
