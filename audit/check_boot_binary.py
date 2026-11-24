#!/usr/bin/env python3
"""Check emitted flat-image invariants for AP counter alignment and GDT Accessed bits.

Usage: check_boot_binary.py TARGET frozen|fixed
Reads only the local build/os.bin and build/os.lst produced by make all.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[2] not in {"frozen", "fixed"}:
    raise SystemExit("usage: check_boot_binary.py TARGET frozen|fixed")

root = Path(sys.argv[1]).resolve()
expected = sys.argv[2]
image = (root / "build" / "os.bin").read_bytes()
boot = (root / "build" / "boot.bin").read_bytes()
listing = (root / "build" / "os.lst").read_text(encoding="utf-8", errors="replace").splitlines()


def label_offset(label: str) -> int:
    for line in listing:
        if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(label)}:", line):
            continue
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        for field in fields[1:]:
            if re.fullmatch(r"[0-9A-Fa-f]{1,16}", field):
                return int(field, 16)
    raise SystemExit(f"FAIL: NASM listing has no emitted offset for {label}:")


tramp = label_offset("tramp")
apcount = label_offset("apcount")
gdt = label_offset("GDT")
if gdt + 24 > len(image):
    raise SystemExit("FAIL: GDT descriptor range is outside os.bin")

aligned = ((apcount - tramp) & 3) == 0
smap_signature_check = b"\x3d\x50\x41\x4d\x53" in boot
code_access = image[gdt + 8 + 5]
data_access = image[gdt + 16 + 5]
observed = (code_access, data_access)

if expected == "frozen":
    if smap_signature_check:
        raise SystemExit("FAIL: frozen boot.bin unexpectedly contains cmp eax, 0x534D4150")
    if aligned:
        raise SystemExit(f"FAIL: expected unaligned apcount, tramp=0x{tramp:x}, apcount=0x{apcount:x}")
    if observed != (0x9A, 0x92):
        raise SystemExit(f"FAIL: frozen GDT access bytes are {observed!r}, expected (0x9a, 0x92)")
else:
    if not smap_signature_check:
        raise SystemExit("FAIL: fixed boot.bin lacks cmp eax, 0x534D4150")
    if not aligned:
        raise SystemExit(f"FAIL: expected aligned apcount, tramp=0x{tramp:x}, apcount=0x{apcount:x}")
    if observed != (0x9B, 0x93):
        raise SystemExit(f"FAIL: fixed GDT access bytes are {observed!r}, expected (0x9b, 0x93)")

print(
    f"PASS: {expected}: tramp=0x{tramp:x}, apcount=0x{apcount:x}, "
    f"relative_alignment={int(aligned)}, GDT_access=(0x{code_access:02x},0x{data_access:02x}), "
    f"E820_SMAP_signature_check={int(smap_signature_check)}"
)
print("LIMIT: emitted-image assertions only; no AP startup, descriptor mutation, or malformed-BIOS runtime was exercised")
