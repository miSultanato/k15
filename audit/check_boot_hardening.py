#!/usr/bin/env python3
"""Source-level differential checks for four low-cost boot hardening fixes.

Usage: check_boot_hardening.py BOUNTY FIXED CURRENT
This does not boot an image or claim runtime exploitability. It checks that
specific source-level hardening changes are absent from the frozen bounty
revision and present in two pinned upstream revisions.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit("usage: check_boot_hardening.py BOUNTY FIXED CURRENT")

bounty, fixed, current = (Path(p).resolve() for p in sys.argv[1:])


def read(root: Path, name: str) -> str:
    return (root / name).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("FAIL: " + message)


def apcount_padding(source: str) -> bool:
    match = re.search(r"(?m)^\s*apcount:\s*dd\s+0", source)
    if not match:
        return False
    before = source[max(0, match.start() - 220):match.start()]
    return bool(re.search(r"(?m)^\s*times\s+\(tramp\s*-\s*\$\)\s*&\s*3\s+db\s+0", before))


def gdt_access_bytes(source: str) -> tuple[int, int]:
    match = re.search(
        r"(?m)^GDT:\s*dq\s+0[^\n]*\n\s*dq\s+(0x[0-9A-Fa-f]+)[^\n]*\n\s*dq\s+(0x[0-9A-Fa-f]+)",
        source,
    )
    if not match:
        raise SystemExit("FAIL: could not parse GDT code/data descriptors")
    code, data = (int(value, 16) for value in match.groups())
    return (code >> 40) & 0xFF, (data >> 40) & 0xFF


def e820_signature_check(source: str) -> bool:
    return bool(re.search(r"(?im)^\s*cmp\s+eax,\s*0x534D4150\b", source))


def name_hostname_guard(makefile: str) -> bool:
    return bool(
        re.search(r"(?m)^ifeq\s*\(\$\(origin NAME\),environment\)\s*$", makefile)
        and re.search(r"(?m)^ifeq\s*\(\$\(NAME\),\$\(shell hostname\)\)\s*$", makefile)
        and re.search(r"(?m)^NAME\s*:=\s*$", makefile)
    )


def inspect(label: str, root: Path) -> dict[str, object]:
    os_source = read(root, "src/os.asm")
    boot_source = read(root, "src/boot.asm")
    makefile = read(root, "Makefile")
    return {
        "label": label,
        "apcount_aligned": apcount_padding(os_source),
        "gdt_access_bytes": gdt_access_bytes(os_source),
        "e820_smap_check": e820_signature_check(boot_source),
        "name_hostname_guard": name_hostname_guard(makefile),
    }


old = inspect("frozen-bounty", bounty)
first = inspect("first-upstream-fix", fixed)
latest = inspect("current-upstream", current)

require(old["apcount_aligned"] is False, "expected frozen apcount to lack 4-byte padding")
require(old["gdt_access_bytes"] == (0x9A, 0x92), "unexpected frozen GDT descriptor bytes")
require(old["e820_smap_check"] is False, "unexpected frozen E820 SMAP signature check")
require(old["name_hostname_guard"] is False, "unexpected frozen NAME/hostname guard")

for result in (first, latest):
    require(result["apcount_aligned"] is True, f"{result['label']}: apcount padding missing")
    require(result["gdt_access_bytes"] == (0x9B, 0x93), f"{result['label']}: GDT Accessed bits missing")
    require(result["e820_smap_check"] is True, f"{result['label']}: E820 SMAP check missing")
    require(result["name_hostname_guard"] is True, f"{result['label']}: NAME/hostname guard missing")

for result in (old, first, latest):
    print(
        f"{result['label']}: apcount_aligned={result['apcount_aligned']}, "
        f"GDT_access=(0x{result['gdt_access_bytes'][0]:02x},0x{result['gdt_access_bytes'][1]:02x}), "
        f"E820_SMAP_check={result['e820_smap_check']}, "
        f"NAME_hostname_guard={result['name_hostname_guard']}"
    )

print("PASS: four source-level boot/build hardening deltas match the expected revisions")
print("LIMIT: static source comparison only; no malformed-BIOS runtime test or image-byte assertion")
