#!/usr/bin/env python3
"""Local-only regression probe for frozen bounty ClientHello length handling.

The inner 24-bit handshake length is varied while the outer TLS record retains
the complete, valid ClientHello. The frozen bounty image is expected to accept
all variants because it bounds parsing by the outer record payload.
This does not contact 15kb.org.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "target").resolve()
sys.path.insert(0, str(target / "tools"))
from tlsclient import hello_record  # noqa: E402


def exchange(wire: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(wire)
        response = bytearray()
        while len(response) < 7:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)


def main() -> None:
    record = hello_record()
    if record[0] != 22 or record[5] != 1:
        raise SystemExit("FAIL: TLS client did not create a one-record ClientHello")
    body = record[5:]
    declared = int.from_bytes(body[1:4], "big")
    if declared != len(body) - 4:
        raise SystemExit("FAIL: generated ClientHello has inconsistent initial length")

    cases = (
        ("zero", 0),
        ("one byte short", declared - 1),
        ("one byte long", declared + 1),
        ("maximum 24-bit length", 0xFFFFFF),
    )
    for label, claimed_length in cases:
        malformed = body[:1] + claimed_length.to_bytes(3, "big") + body[4:]
        wire = bytes((22, 3, 1)) + len(malformed).to_bytes(2, "big") + malformed
        response = exchange(wire)
        if len(response) >= 6 and response[0] == 22 and response[5] == 2:
            print(f"PASS: accepts complete ClientHello with inner length {label}")
            continue
        if len(response) >= 7 and response[0] == 21:
            detail = f"TLS alert {response[6]}"
        else:
            detail = f"unexpected response {response[:32].hex()}"
        raise SystemExit(f"FAIL: rejected inner length {label}: {detail}")

    print("LIMIT: confirms inner handshake length is not enforced; not a key disclosure or memory-safety exploit")


if __name__ == "__main__":
    main()
