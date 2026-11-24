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
        chunk = sock.recv(65536)
        if not chunk:
            break
        pending.extend(chunk)
    return parsed


def client_hello_without_key_share(hello: bytes) -> bytes:
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
    extensions = body[ext_start:ext_end]
    kept = bytearray()
    found = False
    i = 0
    while i < len(extensions):
        if i + 4 > len(extensions):
            raise RuntimeError("truncated ClientHello extension header")
        kind = int.from_bytes(extensions[i : i + 2], "big")
        size = int.from_bytes(extensions[i + 2 : i + 4], "big")
        end = i + 4 + size
        if end > len(extensions):
            raise RuntimeError("truncated ClientHello extension")
        if kind == 51:
            found = True
        else:
            kept.extend(extensions[i:end])
        i = end
    if not found:
        raise RuntimeError("OpenSSL ClientHello did not contain key_share extension")
    new_body = body[:ext_len_pos] + len(kept).to_bytes(2, "big") + bytes(kept)
    new_hs = b"\x01" + len(new_body).to_bytes(3, "big") + new_body
    return hello[:3] + len(new_hs).to_bytes(2, "big") + new_hs


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


def main():
    normal = tlsclient.hello_record()
    if len(normal) < 44 or normal[0] != 22 or normal[5] != 1:
        raise SystemExit("FAIL: expected an OpenSSL ClientHello record")
    sid_len = normal[43]
    if not 0 < sid_len <= 32:
        raise SystemExit(f"FAIL: unexpected legacy_session_id length {sid_len}")

    normal_result = inspect_flight(normal, "normal ClientHello")
    if normal_result is None:
        raise SystemExit("FAIL: no valid ServerHello response to normal ClientHello")
    sent_ccs = normal_result["second_type"] == 20
    if mode == "expect" and sent_ccs:
        raise SystemExit("FAIL: expected missing dummy CCS on frozen normal path")
    if mode == "expect" and not sent_ccs:
        print("PASS: frozen image omitted dummy CCS after normal ServerHello")

    hrr_hello = client_hello_without_key_share(normal)
    hrr_result = inspect_flight(hrr_hello, "ClientHello without key_share")
    if hrr_result is not None and hrr_result["hrr"]:
        second = hrr_result["second_type"]
        if second == 20:
            print("OBSERVED: HelloRetryRequest path sent dummy CCS")
        elif second is not None:
            print("OBSERVED: HelloRetryRequest path omitted dummy CCS")
    else:
        print("OBSERVED: this ClientHello did not elicit a HelloRetryRequest")


if __name__ == "__main__":
    main()
