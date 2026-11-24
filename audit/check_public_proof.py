#!/usr/bin/env python3
"""Offline verification of the public cross-curve bounty proof.

Reads only the public proof committed on the frozen bounty branch. It does not
contact 15kb.org, read a certificate/private key, or attempt key recovery.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/tools").resolve()))
import bounty


def main() -> None:
    proof_path = Path(sys.argv[2] if len(sys.argv) > 2 else "target/bounty.proof")
    text = proof_path.read_text(encoding="utf-8")
    match = re.search(r"^# k15 cross-curve DLEQ proof .* for (bc1[0-9a-z]+)$", text, re.MULTILINE)
    if not match:
        raise SystemExit("FAIL: proof header has no expected Bitcoin address")

    raw = bounty.parse_proof(text)
    q1, q2, address = bounty.verify_xcurve(raw)
    if address != match.group(1):
        raise SystemExit("FAIL: verified secp256k1 public key does not match proof header")
    if len(raw) != 41172:
        raise SystemExit(f"FAIL: unexpected binary proof length {len(raw)}")

    print("PASS: public cross-curve proof verifies without a TLS connection or private key")
    print(f"PASS: proof binds P-256 and secp256k1 public keys to {address}")
    print(f"INFO: proof version={raw[0]}, flip={raw[1]}, binary_bytes={len(raw)}")
    print(f"INFO: P-256 public key={q1.hex()}")
    print(f"INFO: secp256k1 public key={q2.hex()}")
    print("LIMIT: proof verification establishes the public key relation, not knowledge of the private scalar")


if __name__ == "__main__":
    main()
