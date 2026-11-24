#!/usr/bin/env python3
"""Check TLS 1.3 dummy ChangeCipherSpec on normal and HelloRetryRequest paths.

Uses synthetic OpenSSL ClientHellos and inspects only local QEMU responses.
Usage: test_dummy_ccs.py TARGET [expect|observe]
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

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


def client_hello_with_p256_key_share(hello: bytes) -> bytes:
    if len(hello) < 9 or hello[0] != 22 or hello[5] != 1:
        raise RuntimeError("expected a single TLS ClientHello record")
    hs_len = int.from_bytes(hello[6:9], "big")
    body = hello[9 : 9 + hs_len]
    if len(body) != hs_len or len(body) < 35:
        raise RuntimeError("truncated ClientHello body")
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    cipher_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2 + cipher_len
    comp_len = body[pos]
    pos += 1 + comp_len
    ext_len_pos = pos
    ext_len = int.from_bytes(body[pos : pos + 2], "big")
    ext_start = pos + 2
    ext_end = ext_start + ext_len
    if ext_end != len(body):
        raise RuntimeError("ClientHello extension length does not match body")

    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    point = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    share_entry = b"\x00\x17" + len(point).to_bytes(2, "big") + point
    share_data = len(share_entry).to_bytes(2, "big") + share_entry

    kept = bytearray()
    found_share = False
    found_groups = False
    extensions = body[ext_start:ext_end]
    i = 0
    while i < len(extensions):
        if i + 4 > len(extensions):
            raise RuntimeError("truncated ClientHello extension header")
        kind = int.from_bytes(extensions[i : i + 2], "big")
        size = int.from_bytes(extensions[i + 2 : i + 4], "big")
        end = i + 4 + size
        if end > len(extensions):
            raise RuntimeError("truncated ClientHello extension")
        data = extensions[i + 4 : end]
        if kind == 51:
            kept.extend(kind.to_bytes(2, "big") + len(share_data).to_bytes(2, "big") + share_data)
            found_share = True
        elif kind == 10:
            if len(data) < 2:
                raise RuntimeError("malformed supported_groups extension")
            groups_len = int.from_bytes(data[:2], "big")
            groups = [data[j : j + 2] for j in range(2, 2 + groups_len, 2)]
            if b"\x00\x1d" not in groups:
                groups.append(b"\x00\x1d")
            if b"\x00\x17" not in groups:
                groups.append(b"\x00\x17")
            group_data = b"".join(groups)
            new_data = len(group_data).to_bytes(2, "big") + group_data
            kept.extend(kind.to_bytes(2, "big") + len(new_data).to_bytes(2, "big") + new_data)
            found_groups = True
        else:
            kept.extend(extensions[i:end])
        i = end
    if not found_share:
        raise RuntimeError("OpenSSL ClientHello did not contain key_share extension")
    if not found_groups:
        raise RuntimeError("OpenSSL ClientHello did not contain supported_groups extension")

    new_body = body[:ext_len_pos] + len(kept).to_bytes(2, "big") + bytes(kept)
    new_hs = b"\x01" + len(new_body).to_bytes(3, "big") + new_body
    return hello[:3] + len(new_hs).to_bytes(2, "big") + new_hs

