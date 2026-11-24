#!/usr/bin/env python3
"""Exercise the cross-curve DLEQ proof generator with synthetic scalars only.

Usage: python3 audit/test_public_proof.py TARGET/tools
No certificate, private-key file, network access or output artifact is used.
"""
from __future__ import annotations

import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit(__doc__.strip())

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
import bounty


def must_reject(call, label: str) -> None:
    try:
        call()
    except ValueError:
        print(f"PASS: {label} rejected")
        return
    raise SystemExit(f"FAIL: {label} was accepted")


def main() -> None:
    cases = (
        ("flip-0", 1, 0),
        ("flip-1", bounty.N_R1 - 42, 1),
    )
    for label, scalar, expected_flip in cases:
        raw = bounty.prove_xcurve(scalar)
        if len(raw) != 41172 or raw[0] != 1 or raw[1] != expected_flip:
            raise SystemExit(f"FAIL: {label} proof header or length mismatch")
        q1_expected = bounty.R1.mul(scalar, bounty.R1.G)
        q2_expected = bounty.K1.mul(scalar, bounty.K1.G)
        q1, q2, addr = bounty.verify_xcurve(raw, q1_expected)
        if q1 != bounty.R1.encode(q1_expected):
            raise SystemExit(f"FAIL: {label} P-256 public key mismatch")
        if q2 != bounty.K1.encode(q2_expected):
            raise SystemExit(f"FAIL: {label} secp256k1 public key mismatch")
        if addr != bounty.address(scalar):
            raise SystemExit(f"FAIL: {label} Bitcoin address mismatch")
        print(f"PASS: {label} cross-curve proof verifies for synthetic scalar")
        print(f"PASS: {label} proof binds the same scalar in both groups")

        corrupted = bytearray(raw)
        corrupted[300] ^= 1
        must_reject(lambda: bounty.verify_xcurve(bytes(corrupted)), f"{label} corrupted proof")
        wrong_q1 = bounty.R1.mul((scalar + 1) % bounty.N_R1, bounty.R1.G)
        must_reject(lambda: bounty.verify_xcurve(raw, wrong_q1), f"{label} mismatched certificate key")

    print("PASS: flip-0 and flip-1 proof paths; no private key or proof artifact written")


if __name__ == "__main__":
    main()
