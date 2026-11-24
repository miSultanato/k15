#!/usr/bin/env python3
"""Local-only ClientHello framing probe for old/new k15 source revisions.

Usage: test_clienthello_framing.py TARGET accept|reject
Only connects to 127.0.0.1. It never contacts 15kb.org.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[2] not in {"accept", "reject"}:
    raise SystemExit("usage: test_clienthello_framing.py TARGET accept|reject")

target = Path(sys.argv[1]).resolve()
expected = sys.argv[2]
sys.path.insert(0, str(target / "tools"))
from tlsclient import hello_record  # noqa: E402

SERVER_HELLO = bytes.fromhex("1603030203")
DECODE_ERROR = bytes.fromhex("15030300020232")


def exchange(wire: bytes) -> bytes:
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
            sock.settimeout(2)
            sock.sendall(wire)
            while len(response) < 7:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except (ConnectionError, OSError, TimeoutError):
        pass
    return bytes(response)


def check(label: str, response: bytes) -> None:
    if expected == "accept":
        ok = response.startswith(SERVER_HELLO)
        wanted = "ServerHello"
    else:
        ok = response.startswith(DECODE_ERROR)
        wanted = "fatal decode_error alert"
    if not ok:
        raise SystemExit(
            f"FAIL: {label}: expected {wanted}, got {response[:32].hex() or 'no response'}"
        )
    print(f"PASS: {label}: {wanted}")


def main() -> None:
    record = hello_record()
    if record[0] != 22 or record[5] != 1:
        raise SystemExit("FAIL: TLS client did not create a one-record ClientHello")
    body = record[5:]
    declared = int.from_bytes(body[1:4], "big")
    if declared != len(body) - 4:
        raise SystemExit("FAIL: generated ClientHello has inconsistent initial length")

    cases = (
        ("inner length zero", 0),
        ("inner length one byte short", declared - 1),
        ("inner length one byte long", declared + 1),
        ("inner length maximum 24-bit", 0xFFFFFF),
    )
    for label, claimed_length in cases:
        malformed = body[:1] + claimed_length.to_bytes(3, "big") + body[4:]
        wire = bytes((22, 3, 1)) + len(malformed).to_bytes(2, "big") + malformed
        check(label, exchange(wire))

    # Keep the complete original body on TCP but declare one byte less in the
    # enclosing TLS record. The final body byte is outside that record.
    outer_short = bytes((22, 3, 1)) + (len(body) - 1).to_bytes(2, "big") + body
    check("outer record length one byte short", exchange(outer_short))

    print(f"RESULT: all framing cases match expected={expected}")


if __name__ == "__main__":
    main()
