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
    if int.from_bytes(record[3:5], "big") != len(record) - 5:
        raise RuntimeError("expected one complete ClientHello record")
    handshake = bytearray(record[5:])
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


def inspect_flight(hello: bytes, label: str):
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(3)
    try:
        sid_len = hello[43]
        sock.sendall(hello)
        parsed = parse_records(sock, 2)
        if not parsed:
            print(f"OBSERVED: {label}: no server TLS response")
            return None
        first_type, first_body = parsed[0]
        if first_type != 22 or len(first_body) < 38 or first_body[0] != 2:
            print(
                f"OBSERVED: {label}: first record is not ServerHello; "
                f"type={first_type}, body={first_body[:12].hex()}"
            )
            return None
        is_hrr = first_body[6:38] == HRR_RANDOM
        if len(parsed) < 2:
            print(f"OBSERVED: {label}: ServerHello received but no second record")
            return {"sid_len": sid_len, "hrr": is_hrr, "second_type": None}
        second_type = parsed[1][0]
        print(
            f"OBSERVED: {label}: session_id={sid_len}, "
            f"HRR={is_hrr}, record_after_serverhello={second_type}"
        )
        return {"sid_len": sid_len, "hrr": is_hrr, "second_type": second_type}
    finally:
        sock.close()


def main() -> None:
    normal = tlsclient.hello_record()
    if len(normal) < 44 or normal[0] != 22 or normal[5] != 1:
        raise SystemExit("FAIL: expected an OpenSSL ClientHello record")
    sid_len = normal[43]
    if not 0 < sid_len <= 32:
        raise SystemExit(f"FAIL: unexpected legacy_session_id length {sid_len}")

    normal_result = inspect_flight(normal, "normal ClientHello")
    if normal_result is None or normal_result["second_type"] is None:
        raise SystemExit("FAIL: incomplete normal ServerHello flight")
    sent_ccs = normal_result["second_type"] == 20
    if mode == "expect" and sent_ccs:
        raise SystemExit("FAIL: expected missing dummy CCS on frozen normal path")
    if mode == "expect" and not sent_ccs:
        print("PASS: frozen image omitted dummy CCS after normal ServerHello")

    hrr_hello = client_hello_without_x25519_share(normal)
    hrr_result = inspect_flight(hrr_hello, "ClientHello without X25519 key_share")
    if hrr_result is not None and hrr_result["hrr"]:
        second = hrr_result["second_type"]
        if second == 20:
            print("OBSERVED: HelloRetryRequest path sent dummy CCS")
        elif second is not None:
            print("OBSERVED: HelloRetryRequest path omitted dummy CCS")
        else:
            print("OBSERVED: HelloRetryRequest path had no second TLS record")
    else:
        print("OBSERVED: this ClientHello did not elicit a HelloRetryRequest")


if __name__ == "__main__":
    main()
