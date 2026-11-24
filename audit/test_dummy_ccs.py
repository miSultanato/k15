#!/usr/bin/env python3
"""Check the TLS 1.3 dummy ChangeCipherSpec after ServerHello on local QEMU.

The test sends an OpenSSL ClientHello with a non-empty legacy_session_id and
inspects only the first two server TLS records. It never contacts production.
Usage: test_dummy_ccs.py TARGET [expect|observe]
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit("usage: test_dummy_ccs.py TARGET [expect|observe]")

mode = sys.argv[2] if len(sys.argv) == 3 else "expect"
if mode not in {"expect", "observe"}:
    raise SystemExit("mode must be expect or observe")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
import tlsclient  # noqa: E402

sock = socket.create_connection(("127.0.0.1", 8443), timeout=5)
sock.settimeout(3)
try:
    hello = tlsclient.hello_record()
    if len(hello) < 44 or hello[0] != 22 or hello[5] != 1:
        raise SystemExit("FAIL: expected an OpenSSL ClientHello record")
    sid_len = hello[43]
    if sid_len == 0:
        raise SystemExit("FAIL: OpenSSL ClientHello has an empty legacy_session_id")
    if sid_len > 32:
        raise SystemExit(f"FAIL: legacy_session_id length {sid_len} exceeds 32")
    sock.sendall(hello)

    response = bytearray()
    parsed: list[tuple[int, bytes]] = []
    while len(parsed) < 2:
        while len(response) >= 5:
            length = int.from_bytes(response[3:5], "big")
            if len(response) < 5 + length:
                break
            parsed.append((response[0], bytes(response[5 : 5 + length])))
            del response[: 5 + length]
            if len(parsed) >= 2:
                break
        if len(parsed) >= 2:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        response.extend(chunk)

    if not parsed:
        raise SystemExit("FAIL: no server TLS record received")
    first_type, first_body = parsed[0]
    if first_type != 22 or len(first_body) < 4 or first_body[0] != 2:
        raise SystemExit(
            "FAIL: first server record was not a ServerHello handshake record; "
            f"type={first_type}, body={first_body[:8].hex()}"
        )
    if len(parsed) < 2:
        raise SystemExit("FAIL: server did not send a second TLS record")
    second_type, _ = parsed[1]
    sent_ccs = second_type == 20
    label = "PASS" if mode == "expect" and not sent_ccs else "OBSERVED"
    print(f"{label}: ClientHello legacy_session_id length={sid_len}")
    print(f"{label}: record immediately after ServerHello has outer type={second_type}")
    if mode == "expect" and sent_ccs:
        raise SystemExit("FAIL: expected missing dummy ChangeCipherSpec, but server sent one")
    if mode == "expect" and not sent_ccs:
        print("PASS: frozen image omitted the required dummy ChangeCipherSpec")
    elif mode == "observe":
        print("OBSERVED: " + ("upstream image sent dummy ChangeCipherSpec" if sent_ccs
                              else "upstream image omitted dummy ChangeCipherSpec"))
finally:
    sock.close()
