#!/usr/bin/env python3
"""Scan one local QEMU guest-RAM snapshot for the synthetic P-256 scalar.

The image contains the key in Montgomery form (d * 2^256 mod n). This checks
for that expected encoding and for the plaintext 32-byte scalar in either byte
order. It never scans the host filesystem or a production machine.
"""
from __future__ import annotations

import mmap
import os
import socket
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

TARGET = Path(sys.argv[1] if len(sys.argv) > 1 else "target").resolve()
MONITOR = sys.argv[2] if len(sys.argv) > 2 else "/tmp/k15-monitor"
RAM_PATH = Path(sys.argv[3] if len(sys.argv) > 3 else "/tmp/k15-guest-ram.bin")
RAM_SIZE = 256 * 1024 * 1024

sys.path.insert(0, str(TARGET / "tools"))
import ec as curve  # noqa: E402


def until_prompt(sock: socket.socket, timeout: int = 60) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while not data.endswith(b"(qemu) "):
        part = sock.recv(65536)
        if not part:
            raise ConnectionError("QEMU monitor closed")
        data.extend(part)
    return bytes(data)


def occurrences(mm: mmap.mmap, needle: bytes) -> int:
    count = 0
    at = 0
    while True:
        at = mm.find(needle, at)
        if at < 0:
            return count
        count += 1
        at += 1


def main() -> None:
    key_path = TARGET / "cert" / "server.key"
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    d = key.private_numbers().private_value
    n = curve.N256
    masked = (d * curve.R) % n

    plaintext_forms = {
        d.to_bytes(32, "little"),
        d.to_bytes(32, "big"),
    }
    masked_forms = {
        masked.to_bytes(32, "little"),
        masked.to_bytes(32, "big"),
    }

    monitor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    monitor.connect(MONITOR)
    until_prompt(monitor)
    command = f"pmemsave 0 0x{RAM_SIZE:x} {RAM_PATH}\n".encode("ascii")
    monitor.sendall(command)
    response = until_prompt(monitor, timeout=120)
    monitor.close()

    if not RAM_PATH.exists():
        print("QEMU monitor response:", response.decode("utf-8", errors="replace")[-1000:])
        raise SystemExit("FAIL: QEMU monitor did not create the guest RAM snapshot")
    size = RAM_PATH.stat().st_size
    if size != RAM_SIZE:
        raise SystemExit(f"FAIL: expected {RAM_SIZE} guest RAM bytes, got {size}")

    with RAM_PATH.open("rb") as file:
        mm = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        plain_hits = sum(occurrences(mm, value) for value in plaintext_forms)
        masked_hits = sum(occurrences(mm, value) for value in masked_forms)
        mm.close()
    RAM_PATH.unlink(missing_ok=True)

    print(f"Guest physical RAM scanned: {size} bytes")
    print(f"Plaintext synthetic scalar encodings found: {plain_hits}")
    print(f"Expected Montgomery-form scalar encodings found: {masked_hits}")
    if plain_hits:
        raise SystemExit("FAIL: plaintext synthetic scalar pattern found in guest RAM")
    if not masked_hits:
        raise SystemExit("FAIL: expected Montgomery-form scalar pattern not found")
    print("PASS: snapshot contains the expected masked scalar and no plaintext 32-byte encoding")
    print("LIMIT: one guest-RAM snapshot; CPU registers, host memory and transient states are not scanned")


if __name__ == "__main__":
    main()
