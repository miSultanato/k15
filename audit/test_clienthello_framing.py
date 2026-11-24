#!/usr/bin/env python3
"""Local-only ClientHello framing and field-validation probes.

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

DECODE_ERROR = bytes.fromhex("15030300020232")


def exchange(wire: bytes, minimum: int = 7) -> bytes:
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
            sock.settimeout(2)
            sock.sendall(wire)
            while len(response) < minimum:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except (ConnectionError, OSError, TimeoutError):
        pass
    return bytes(response)


def check(label: str, response: bytes) -> None:
    if expected == "accept":
        ok = len(response) >= 6 and response[0] == 22 and response[5] == 2
        wanted = "ServerHello"
    else:
        ok = response.startswith(DECODE_ERROR)
        wanted = "fatal decode_error alert"
    if not ok:
        raise SystemExit(
            f"FAIL: {label}: expected {wanted}, got {response[:32].hex() or 'no response'}"
        )
    print(f"PASS: {label}: {wanted}")


def rebuild(ch: bytes) -> bytes:
    handshake = b"\x01" + len(ch).to_bytes(3, "big") + ch
    return bytes((22, 3, 1)) + len(handshake).to_bytes(2, "big") + handshake


def observe(label: str, wire: bytes, minimum: int = 11) -> None:
    response = exchange(wire, minimum)
    if len(response) >= 6 and response[0] == 22 and response[5] == 2:
        legacy = response[9:11].hex() if len(response) >= 11 else "unavailable"
        print(f"OBSERVED: {label}: ServerHello legacy_version=0x{legacy}")
    elif response.startswith(DECODE_ERROR):
        print(f"OBSERVED: {label}: fatal decode_error")
    elif response:
        print(f"OBSERVED: {label}: response={response[:16].hex()}")
    else:
        print(f"OBSERVED: {label}: no response")


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

    outer_short = bytes((22, 3, 1)) + (len(body) - 1).to_bytes(2, "big") + body
    check("outer record length one byte short", exchange(outer_short))
    print(f"RESULT: framing cases match expected={expected}")

    ch = bytearray(body[4:])
    # Session ID length 33 with a fully present 33-byte value.
    sid_pos = 34
    sid_len = ch[sid_pos]
    if sid_len != 32:
        raise SystemExit(f"FAIL: expected 32-byte baseline session ID, got {sid_len}")
    ch33 = bytearray(ch)
    ch33[sid_pos] = 33
    ch33[sid_pos + 1 + sid_len : sid_pos + 1 + sid_len] = b"\xaa"
    observe("legacy_session_id length 33", rebuild(bytes(ch33)))

    # Compression method 1 is invalid for TLS 1.3 (only null compression is legal).
    p = 34
    p += 1 + ch[p]
    cipher_len = int.from_bytes(ch[p : p + 2], "big")
    p += 2 + cipher_len
    comp_len = ch[p]
    if comp_len != 1:
        raise SystemExit(f"FAIL: expected one baseline compression method, got {comp_len}")
    p += 1
    ch_compression = bytearray(ch)
    ch_compression[p] = 1
    observe("non-null compression method", rebuild(bytes(ch_compression)))

    # TLS 1.3 ClientHello legacy_version must be 0x0303.
    ch_version = bytearray(ch)
    ch_version[0:2] = b"\x03\x01"
    observe("ClientHello legacy_version 0x0301", rebuild(bytes(ch_version)))


if __name__ == "__main__":
    main()
