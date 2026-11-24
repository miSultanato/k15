#!/usr/bin/env python3
"""Verify exact and off-by-one TCP RST sequence handling on a local TAP guest."""
from __future__ import annotations

import os
import select
import socket
import struct
import sys
import time

GUEST_IP = socket.inet_aton("10.0.2.15")
HOST_IP = socket.inet_aton("10.64.0.1")
TAP = os.environ.get("TAP", "k2t")
HTTP = b"GET / HTTP/1.1\r\nHost: k15\r\nConnection: close\r\n\r\n"
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(sport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, 80, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, (5 << 12) | flags, 65535, 0, 0) + payload
    pseudo = HOST_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_sum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x5252, 0, 64, 6, 0, HOST_IP, GUEST_IP)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return broadcast + host_mac + b"\x08\x00" + ip + tcp


def parse(data: bytes, sport: int):
    if len(data) < 54 or data[12:14] != b"\x08\x00":
        return None
    if data[23] != 6 or data[26:30] != GUEST_IP or data[30:34] != HOST_IP:
        return None
    tcp = 34
    if int.from_bytes(data[tcp:tcp+2], "big") != 80:
        return None
    if int.from_bytes(data[tcp+2:tcp+4], "big") != sport:
        return None
    ihl = (data[14] & 15) * 4
    tcp = 14 + ihl
    thl = (data[tcp+12] >> 4) * 4
    total = int.from_bytes(data[16:18], "big")
    end = min(len(data), 14 + total)
    return {
        "seq": int.from_bytes(data[tcp+4:tcp+8], "big"),
        "ack": int.from_bytes(data[tcp+8:tcp+12], "big"),
        "flags": data[tcp+13],
        "payload": data[tcp+thl:end],
    }


def receive(sport: int, timeout: float, payload_only: bool = False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline-time.monotonic()))
        if not ready:
            break
        item = parse(sock.recv(65536), sport)
        if item is None:
            continue
        if payload_only and not item["payload"]:
            continue
        return item
    return None


def run_case(offset: int, expected_http: bool, sport: int, isn: int) -> None:
    syn_options = b"\x02\x04\x02\x18"  # MSS 536
    # TCP options are unnecessary for the cookie's sequence check; use the
    # normal fixed 20-byte SYN header, then observe the server's cookie.
    sock.send(frame(sport, isn, 0, 0x02))
    synack = receive(sport, 2.0)
    if synack is None or (synack["flags"] & 0x12) != 0x12:
        raise SystemExit(f"FAIL: no SYN-ACK for RST case offset={offset:+d}")
    client_next = (isn + 1) & 0xFFFFFFFF
    server_next = (synack["seq"] + 1) & 0xFFFFFFFF
    sock.send(frame(sport, client_next, server_next, 0x10))
    sock.send(frame(sport, client_next, server_next, 0x18, HTTP[:1]))
    first_ack = receive(sport, 2.0)
    if first_ack is None or not (first_ack["flags"] & 0x10):
        raise SystemExit(f"FAIL: no ACK after one-byte request prefix, offset={offset:+d}")
    reset_seq = (first_ack["ack"] + offset) & 0xFFFFFFFF
    sock.send(frame(sport, reset_seq, server_next, 0x04))
    time.sleep(0.1)
    # The remainder is deliberately not at the original cookie's first
    # sequence number, so a correctly processed RST cannot be hidden by
    # recreating the SYN-cookie connection.
    sock.send(frame(sport, client_next + 1, server_next, 0x18, HTTP[1:]))
    response = bytearray()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        item = receive(sport, max(0.01, deadline-time.monotonic()), payload_only=True)
        if item is None:
            break
        response.extend(item["payload"])
        if b"HTTP/1." in response:
            break
    observed = response.startswith(b"HTTP/1.")
    if observed != expected_http:
        raise SystemExit(
            f"FAIL: RST sequence offset={offset:+d}: HTTP={observed}, "
            f"expected HTTP={expected_http}, response_bytes={len(response)}"
        )
    expectation = "connection survives" if expected_http else "connection is reset"
    print(
        f"PASS: RST seq offset={offset:+d} from observed ACK 0x{first_ack['ack']:08x}: "
        f"{expectation}"
    )


try:
    run_case(0, False, 52301, 0x63710001)
    run_case(-1, True, 52302, 0x63710002)
    run_case(1, True, 52303, 0x63710003)
    print("RESULT: exact and off-by-one RST sequence checks passed")
finally:
    sock.close()
