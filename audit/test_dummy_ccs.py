#!/usr/bin/env python3
"""Check TLS 1.3 dummy ChangeCipherSpec on normal and HelloRetryRequest paths.

Uses synthetic OpenSSL ClientHellos and inspects only local QEMU responses.
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

HOST, PORT = "127.0.0.1", 8443
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)


def parse_records(sock: socket.socket, count: int = 2):
    pending = bytearray()
    parsed: list[tuple[int, bytes]] = []
    while len(parsed) < count:
        while len(pending) >= 5:
            length = int.from_bytes(pending[3:5], "big")
            if len(pending) < 5 + length:
                break
            parsed.append((pending[0], bytes(pending[5 : 5 + length])))
            del pending[: 5 + length]
            if len(parsed) >= count:
                break
        if len(parsed) >= count:
            break
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        pending.extend(chunk)
    return parsed


def client_hello_without_x25519_share(record: bytes) -> bytes:
    if len(record) < 9 or record[0] != 22 or record[5] != 1:
        raise RuntimeError("expected a single TLS ClientHello record")
    handshake = bytearray(record[5:])
    if int.from_bytes(record[3:5], "big") != len(record) - 5:
        raise RuntimeError("expected one complete ClientHello record")
    p = 38
    p += 1 + handshake[p]
    p += 2 + int.from_bytes(handshake[p : p + 2], "big")
    p += 1 + handshake[p] + 2
    found = False
    while p + 4 <= len(handshake):
        kind = int.from_bytes(handshake[p : p + 2], "big")
        size = int.from_bytes(handshake[p + 2 : p + 4], "big")
        if p + 4 + size > len(handshake):
            raise RuntimeError("truncated ClientHello extension")
        if kind == 51:
            q = p + 6
            while q + 4 <= p + 4 + size:
                share_len = int.from_bytes(handshake[q + 2 : q + 4], "big")
                if handshake[q : q + 2] == b"\x00\x1d":
                    handshake[q : q + 2] = b"\x01\x00"
                    found = True
                q += 4 + share_len
        p += 4 + size
    if not found:
        raise RuntimeError("ClientHello has no X25519 key share to replace")
    body = bytes(handshake)
    return record[:3] + len(body).to_bytes(2, "big") + body

