#!/usr/bin/env python3
"""Local TAP tests for ACK-window handling and peer-MSS enforcement.

Usage: test_tcp_ack_mss.py TARGET [expect|observe]
The tests use raw synthetic TCP segments to the QEMU guest only.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit("usage: test_tcp_ack_mss.py TARGET [expect|observe]")

mode = sys.argv[2] if len(sys.argv) == 3 else "expect"
if mode not in {"expect", "observe"}:
    raise SystemExit("mode must be expect or observe")

GUEST_IP = socket.inet_aton("10.0.2.15")
HOST_IP = socket.inet_aton("10.64.0.1")
TAP = os.environ.get("TAP", "k2t")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6
HTTP = b"GET / HTTP/1.1\r\nHost: k15\r\nConnection: close\r\n\r\n"


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_frame(
    sport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    options: bytes = b"",
) -> bytes:
    if len(options) % 4:
        options += b"\x01" * (4 - len(options) % 4)
    offset = 20 + len(options)
    offset_flags = ((offset // 4) << 12) | flags
    tcp = struct.pack(
        "!HHIIHHHH",
        sport,
        80,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        65535,
        0,
        0,
    ) + options
    pseudo = HOST_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_sum = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x5151, 0, 64, 6, 0, HOST_IP, GUEST_IP)
    ip_sum = checksum(ip)
    ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]
    return broadcast + host_mac + b"\x08\x00" + ip + tcp + payload


def parse_response(frame: bytes, sport: int):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    if frame[23] != 6 or frame[26:30] != GUEST_IP or frame[30:34] != HOST_IP:
        return None
    total = int.from_bytes(frame[16:18], "big")
    ihl = (frame[14] & 15) * 4
    tcp = 14 + ihl
    if len(frame) < tcp + 20 or total < ihl + 20:
        return None
    if int.from_bytes(frame[tcp : tcp + 2], "big") != 80:
        return None
    if int.from_bytes(frame[tcp + 2 : tcp + 4], "big") != sport:
        return None
    thl = (frame[tcp + 12] >> 4) * 4
    if thl < 20 or total < ihl + thl:
        return None
    end = min(len(frame), 14 + total)
    return {
        "seq": int.from_bytes(frame[tcp + 4 : tcp + 8], "big"),
        "ack": int.from_bytes(frame[tcp + 8 : tcp + 12], "big"),
        "flags": frame[tcp + 13],
        "options": frame[tcp + 20 : tcp + thl],
        "payload": frame[tcp + thl : end],
    }


def receive(sport: int, timeout: float = 1.5, want_payload: bool = False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        item = parse_response(sock.recv(65536), sport)
        if item is None:
            continue
        if want_payload and not item["payload"]:
            continue
        return item
    return None


def handshake(sport: int, client_isn: int, mss: int):
    syn_options = b"\x02\x04" + struct.pack("!H", mss)
    sock.send(make_frame(sport, client_isn, 0, 0x02, options=syn_options))
    synack = receive(sport, 2.0)
    if synack is None or (synack["flags"] & 0x12) != 0x12:
        return None
    return synack


def parse_mss(options: bytes):
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        size = options[i + 1]
        if size < 2 or i + size > len(options):
            break
        if kind == 2 and size == 4:
            return int.from_bytes(options[i + 2 : i + 4], "big")
        i += size
    return None


def fetch_after_handshake(
    sport: int, client_isn: int, synack, bad_ack: bool = False, request: bytes = HTTP
):
    server_next = (synack["seq"] + 1) & 0xFFFFFFFF
    client_next = (client_isn + 1) & 0xFFFFFFFF
    sock.send(make_frame(sport, client_next, server_next, 0x10))
    ack = (server_next + 0x10000) & 0xFFFFFFFF if bad_ack else server_next
    sock.send(make_frame(sport, client_next, ack, 0x18, request))
    deadline = time.monotonic() + 2.0
    payloads = []
    while time.monotonic() < deadline:
        item = receive(sport, max(0.01, deadline - time.monotonic()), want_payload=True)
        if item is None:
            break
        payloads.append(item["payload"])
        if b"HTTP/1." in b"".join(payloads):
            break
    return payloads


def report(label: str, success: bool, detail: str) -> None:
    if mode == "expect" and not success:
        raise SystemExit(f"FAIL: {label}: {detail}")
    prefix = "PASS" if mode == "expect" and success else "OBSERVED"
    print(f"{prefix}: {label}: {detail}")


def test_bad_ack() -> None:
    sport, isn = 52001, 0x12345678
    synack = handshake(sport, isn, 536)
    if synack is None:
        report("ACK-window test", False, "no SYN-ACK for control connection")
        return
    payloads = fetch_after_handshake(sport, isn, synack, bad_ack=True)
    response = b"".join(payloads)
    report(
        "ACK-window test",
        response.startswith(b"HTTP/1."),
        "HTTP response received after an ACK beyond server SND.NXT"
        if response.startswith(b"HTTP/1.")
        else f"no HTTP response; captured {len(response)} payload bytes",
    )


def test_http_methods() -> None:
    for sport, isn, method in (
        (52003, 0x3456789A, b"get"),
        (52004, 0x456789AB, b"FOO"),
    ):
        synack = handshake(sport, isn, 536)
        if synack is None:
            print(f"OBSERVED: HTTP method {method.decode()}: no SYN-ACK")
            continue
        request = method + b" / HTTP/1.1\r\nHost: k15\r\nConnection: close\r\n\r\n"
        payloads = fetch_after_handshake(sport, isn, synack, request=request)
        response = b"".join(payloads)
        if response.startswith(b"HTTP/1."):
            print(f"OBSERVED: HTTP method {method.decode()}: response {response[:40]!r}")
        else:
            print(f"OBSERVED: HTTP method {method.decode()}: no HTTP response")


def test_small_mss() -> None:
    sport, isn, peer_mss = 52002, 0x23456789, 100
    synack = handshake(sport, isn, peer_mss)
    if synack is None:
        report("MSS=100 test", False, "guest sent no SYN-ACK (possibly refused the MSS)")
        return
    advertised = parse_mss(synack["options"])
    payloads = fetch_after_handshake(sport, isn, synack, bad_ack=False)
    maximum = max((len(p) for p in payloads), default=0)
    report(
        "MSS=100 test",
        maximum > peer_mss,
        f"peer MSS={peer_mss}, SYN-ACK MSS={advertised}, largest outbound data segment={maximum}",
    )


if __name__ == "__main__":
    try:
        test_bad_ack()
        test_http_methods()
        test_small_mss()
        print(f"RESULT: TCP ACK/MSS probes completed in mode={mode}")
    finally:
        sock.close()
