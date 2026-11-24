#!/usr/bin/env python3
"""Replay one captured SYN-cookie ACK across a local QEMU system_reset.

The test uses only synthetic IPv4/TCP packets on the ephemeral TAP interface.
It proves key rotation only if the same tuple/ISN produces a different cookie
after reset, then checks old-cookie rejection and fresh-cookie acceptance.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

TAP = os.environ.get("TAP", "k2t")
MON = os.environ.get("MON")
if not MON:
    raise SystemExit("MON must name the QEMU human-monitor Unix socket")

GUEST_IP = socket.inet_aton("10.0.2.15")
HOST_IP = socket.inet_aton("10.64.0.1")
SPORT = 52991
ISN = 0x6A15C001
HTTP_OLD = b"GET / HTTP/1.1\r\nHost: k15\r\nX-Replay: old-cookie\r\nConnection: close\r\n\r\n"
HTTP_NEW = b"GET / HTTP/1.1\r\nHost: k15\r\nX-Replay: fresh-cookie\r\nConnection: close\r\n\r\n"

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
HOST_MAC = sock.getsockname()[4]


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(
    seq: int, ack: int, flags: int, payload: bytes = b"", options: bytes = b""
) -> bytes:
    if len(options) % 4:
        options += b"\x01" * (4 - len(options) % 4)
    tcp_header_len = 20 + len(options)
    if tcp_header_len > 60:
        raise ValueError("TCP options exceed the 40-byte header limit")
    tcp = struct.pack("!HHIIHHHH", SPORT, 80, seq & 0xffffffff,
                      ack & 0xffffffff, ((tcp_header_len // 4) << 12) | flags,
                      65535, 0, 0) + options + payload
    pseudo = HOST_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     0x6A15, 0, 64, 6, 0, HOST_IP, GUEST_IP)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\xff" * 6 + HOST_MAC + b"\x08\x00" + ip + tcp


def receive(timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        packet = sock.recv(65536)
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        if packet[23] != 6 or packet[26:30] != GUEST_IP or packet[30:34] != HOST_IP:
            continue
        ip_len = (packet[14] & 15) * 4
        tcp = 14 + ip_len
        if len(packet) < tcp + 20:
            continue
        if int.from_bytes(packet[tcp:tcp+2], "big") != 80:
            continue
        if int.from_bytes(packet[tcp+2:tcp+4], "big") != SPORT:
            continue
        tcp_len = (packet[tcp+12] >> 4) * 4
        total = int.from_bytes(packet[16:18], "big")
        if tcp_len < 20 or total < ip_len + tcp_len:
            continue
        end = min(len(packet), 14 + total)
        return {
            "seq": int.from_bytes(packet[tcp+4:tcp+8], "big"),
            "ack": int.from_bytes(packet[tcp+8:tcp+12], "big"),
            "flags": packet[tcp+13],
            "payload": packet[tcp+tcp_len:end],
        }
    return None


def drain_rx() -> None:
    """Discard queued frames so a pre-reset SYN-ACK cannot masquerade as fresh."""
    while True:
        ready, _, _ = select.select([sock], [], [], 0)
        if not ready:
            return
        sock.recv(65536)


def syn_cookie(timeout: float = 30.0) -> int:
    drain_rx()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock.send(frame(ISN, 0, 0x02, options=b"\x02\x04\x02\x18"))
        item = receive(0.45)
        if item and (item["flags"] & 0x12) == 0x12 and item["ack"] == ((ISN + 1) & 0xffffffff):
            return item["seq"]
    raise RuntimeError("no SYN-ACK received after boot/reset")


def read_monitor_prompt(monitor: socket.socket) -> bytes:
    response = bytearray()
    deadline = time.monotonic() + 3
    while b"(qemu) " not in response:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"QEMU monitor prompt timeout: {bytes(response)!r}")
        try:
            chunk = monitor.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise RuntimeError(f"QEMU monitor closed before prompt: {bytes(response)!r}")
        response.extend(chunk)
    return bytes(response)


def monitor_command(command: str) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(0.5)
        monitor.connect(MON)
        read_monitor_prompt(monitor)
        monitor.sendall(command.encode("ascii") + b"\n")
        return read_monitor_prompt(monitor)


def reset_guest() -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
                monitor.settimeout(0.5)
                monitor.connect(MON)
                read_monitor_prompt(monitor)  # consume the greeting prompt first
                monitor.sendall(b"system_reset\n")
                response = read_monitor_prompt(monitor)  # wait for command completion
                if b"Error" in response:
                    raise RuntimeError(f"QEMU system_reset failed: {response!r}")
            print(f"OBSERVED: QEMU monitor acknowledged system_reset: {response!r}")
            time.sleep(2.0)  # allow firmware, bootloader and guest initialization to finish
            return
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.1)
    raise RuntimeError("QEMU monitor socket did not become available")


def request_with_cookie(server_isn: int, payload: bytes, timeout: float = 2.5) -> bytes:
    client_next = (ISN + 1) & 0xffffffff
    server_next = (server_isn + 1) & 0xffffffff
    sock.send(frame(client_next, server_next, 0x10))
    sock.send(frame(client_next, server_next, 0x18, payload))
    received = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        item = receive(max(0.01, deadline - time.monotonic()))
        if item is None:
            break
        received.extend(item["payload"])
        if b"HTTP/1." in received:
            break
    return bytes(received)


try:
    old_cookie = syn_cookie()
    print(f"OBSERVED: pre-reset SYN cookie=0x{old_cookie:08x}")
    new_cookie = old_cookie

    # A 26-bit cookie collision is possible. Permit two independent guest
    # resets before treating an unchanged value as a failed rotation check.
    for attempt in range(1, 4):
        reset_guest()
        # Drop any SYN-ACK queued before or during the monitor reset before
        # issuing the post-reset SYN with the same tuple and client ISN.
        drain_rx()
        try:
            new_cookie = syn_cookie()
        except RuntimeError:
            print("DIAGNOSTIC: QEMU status after reset")
            print(monitor_command("info status").decode("utf-8", errors="replace"))
            print("DIAGNOSTIC: QEMU CPU registers after reset")
            print(monitor_command("info registers").decode("utf-8", errors="replace"))
            print("DIAGNOSTIC: QEMU network devices after reset")
            print(monitor_command("info network").decode("utf-8", errors="replace"))
            raise
        print(f"OBSERVED: post-reset attempt {attempt} SYN cookie=0x{new_cookie:08x}")
        if new_cookie != old_cookie:
            break
    if new_cookie == old_cookie:
        raise SystemExit("FAIL: SYN cookie did not change across three guest resets")

    old_response = request_with_cookie(old_cookie, HTTP_OLD)
    if b"HTTP/1." in old_response:
        raise SystemExit("FAIL: pre-reset cookie ACK was accepted after key regeneration")
    print("PASS: pre-reset SYN-cookie ACK rejected after guest reset/key regeneration")

    fresh_response = request_with_cookie(new_cookie, HTTP_NEW)
    if not fresh_response.startswith(b"HTTP/1."):
        raise SystemExit(
            "FAIL: fresh post-reset SYN-cookie ACK did not process HTTP "
            f"(captured {len(fresh_response)} payload bytes)"
        )
    print("PASS: fresh post-reset SYN-cookie ACK accepted and HTTP request processed")
    print("RESULT: SYN-cookie boot-key rotation and stale-cookie rejection verified")
finally:
    sock.close()
