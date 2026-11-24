#!/usr/bin/env python3
"""Deterministic IPv4-checksum and ARP-field probes over the local QEMU TAP link.

Usage: test_ip_arp_validation.py TARGET [expect|observe]
Only synthetic frames are sent to the local guest at 10.0.2.15.
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
    raise SystemExit("usage: test_ip_arp_validation.py TARGET [expect|observe]")

mode = sys.argv[2] if len(sys.argv) == 3 else "expect"
if mode not in {"expect", "observe"}:
    raise SystemExit("mode must be expect or observe")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
import tlsclient  # noqa: E402

TAP = os.environ.get("TAP", "k2t")
GUEST_IP = socket.inet_aton("10.0.2.15")
HOST_IP = socket.inet_aton("10.0.2.34")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
ETH_BROADCAST = b"\xff" * 6


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_syn(sport: int, bad_ip_checksum: bool) -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, 80, 0x12340000 + sport, 0, 0x5002, 65535, 0, 0)
    pseudo = HOST_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_sum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x4242, 0, 64, 6, 0, HOST_IP, GUEST_IP)
    ip_sum = checksum(ip)
    if bad_ip_checksum:
        ip_sum ^= 1
    ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]
    return ETH_BROADCAST + host_mac + b"\x08\x00" + ip + tcp


def is_synack(frame: bytes, sport: int) -> bool:
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return False
    ihl = (frame[14] & 15) * 4
    if frame[23] != 6 or len(frame) < 14 + ihl + 20:
        return False
    if frame[26:30] != GUEST_IP or frame[30:34] != HOST_IP:
        return False
    tcp = 14 + ihl
    flags = frame[tcp + 13]
    return (
        int.from_bytes(frame[tcp : tcp + 2], "big") == 80
        and int.from_bytes(frame[tcp + 2 : tcp + 4], "big") == sport
        and (flags & 0x12) == 0x12
    )


def wait_for(predicate, timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        frame = sock.recv(65536)
        if predicate(frame):
            return True
    return False


def test_ipv4_checksum() -> bool:
    results = []
    for sport, bad in ((51080, False), (51081, True)):
        sock.send(ipv4_syn(sport, bad))
        results.append(wait_for(lambda f, p=sport: is_synack(f, p)))
    for bad, got in zip((False, True), results):
        desc = "invalid" if bad else "valid"
        if mode == "expect" and not got:
            raise SystemExit(f"FAIL: guest did not answer SYN with {desc} IPv4 checksum")
        label = "PASS" if mode == "expect" and got else "OBSERVED"
        print(f"{label}: SYN with {desc} IPv4 header checksum " +
              ("received SYN-ACK" if got else "received no SYN-ACK"))
    return all(results)


def arp_request(hrd: int, pro: int, hln: int, plen: int, op: int = 1) -> bytes:
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        hrd,
        pro,
        hln,
        plen,
        op,
        host_mac,
        HOST_IP,
        bytes(6),
        GUEST_IP,
    )
    return ETH_BROADCAST + host_mac + b"\x08\x06" + arp


def is_arp_reply(frame: bytes) -> bool:
    return len(frame) >= 42 and frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x02"


def test_arp_fields() -> bool:
    cases = (
        ("hardware type 2", 2, 0x0800, 6, 4),
        ("protocol type IPv6", 1, 0x86DD, 6, 4),
        ("hardware length 1", 1, 0x0800, 1, 4),
        ("protocol length 1", 1, 0x0800, 6, 1),
    )
    observed = []
    for label, hrd, pro, hln, plen in cases:
        sock.send(arp_request(hrd, pro, hln, plen))
        got = wait_for(is_arp_reply)
        observed.append(got)
        if mode == "expect" and not got:
            raise SystemExit(f"FAIL: malformed ARP request ({label}) got no reply")
        status = "PASS" if mode == "expect" and got else "OBSERVED"
        print(f"{status}: malformed ARP {label}: " + ("reply" if got else "no reply"))
    return all(observed)


def guest_alive() -> bool:
    pid = os.environ.get("QEMU_PID")
    return not pid or os.path.exists("/proc/%s" % pid)


def real_client() -> bool:
    sock = socket.create_connection(
        ("10.0.2.15", 443), timeout=10, source_address=("10.0.2.33", 0)
    )
    tls = tlsclient.context().wrap_socket(sock, server_hostname=tlsclient.NAME)
    try:
        request = b"GET / HTTP/1.1\r\nHost: " + tlsclient.NAME.encode() + b"\r\n\r\n"
        tls.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = tls.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        return response.startswith(b"HTTP/1.1 200")
    finally:
        tls.close()


if __name__ == "__main__":
    try:
        test_ipv4_checksum()
        test_arp_fields()
        if not guest_alive() or not real_client():
            raise SystemExit("FAIL: guest did not remain healthy after protocol probes")
        print(f"RESULT: IPv4/ARP validation probes completed in mode={mode}; guest healthy")
    finally:
        sock.close()
