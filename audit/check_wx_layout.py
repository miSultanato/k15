#!/usr/bin/env python3
"""Assert the emitted short-site layout maps the final site byte as NX or executable.

The page tables are initialized at runtime. This check reconstructs the exact
CODEPG threshold from the emitted listing and the revision's source formula,
then evaluates the page containing the final byte of the synthetic site.

Usage: check_wx_layout.py TARGET alive|reset
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PAGE_SIZE = 4096
IMAGE_BASE = 0x100000


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def label_offset(listing: list[str], label: str) -> int:
    for line in listing:
        if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(label)}:", line):
            continue
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        for field in fields[1:]:
            if re.fullmatch(r"[0-9A-Fa-f]{1,16}", field):
                return int(field, 16)
    fail(f"NASM listing has no emitted offset for {label}:")
    raise AssertionError


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"alive", "reset"}:
        fail("usage: check_wx_layout.py TARGET alive|reset")
    root = Path(sys.argv[1]).resolve()
    expected = sys.argv[2]
    build = root / "build-wx-short"
    source = (root / "src/os.asm").read_text(encoding="utf-8")
    image = (build / "os.bin").read_bytes()
    site = (build / "site.bin").read_bytes()
    listing = (build / "os.lst").read_text(encoding="utf-8", errors="replace").splitlines()

    if not site or len(site) >= PAGE_SIZE:
        fail(f"expected a non-empty synthetic site smaller than one page, got {len(site)} bytes")
    if image[-len(site):] != site:
        fail("site.bin is not the exact tail of the emitted os.bin")
    if site[-1] != 0xC3:
        fail(f"synthetic site's final byte is 0x{site[-1]:02x}, expected RET (0xc3)")

    site_offset = len(image) - len(site)
    if expected == "alive":
        if not re.search(
            r"(?m)^CODEPG\s+equ\s+0x100\s+\+\s+\(\(codend\s*-\s*mb\s*\+\s*0xFFF\)\s*>>\s*12\)",
            source,
        ):
            fail("frozen source no longer has the expected codend-based CODEPG formula")
        # TWO32 is the first emitted datum immediately after the zero-byte codend label.
        codend = label_offset(listing, "TWO32")
        codepg = 0x100 + ((codend + 0xFFF) >> 12)
        delta = 0
    else:
        if not re.search(
            r"(?m)^CODEPG\s+equ\s+\(\(0x100000\s+\+\s+DELTA\s+\+\s+\(xend\s*-\s*mb\)\)\s*>>\s*12\)",
            source,
        ):
            fail("upstream source no longer has the expected xend/DELTA CODEPG formula")
        delta_text = (build / "delta").read_text(encoding="ascii").strip()
        match = re.fullmatch(r"-DDELTA=(\d+)", delta_text)
        if not match:
            fail(f"could not parse emitted DELTA definition: {delta_text!r}")
        delta = int(match.group(1))
        apcount = label_offset(listing, "apcount")
        # xend follows the final real-mode trampoline instructions: HLT; JMP .no.
        # Their exact bytes end at xend, followed by at most three alignment bytes.
        xend_candidates = [
            end for end in range(max(3, apcount - 3), apcount + 1)
            if image[end - 3 : end] == bytes.fromhex("f4 eb fd")
        ]
        if len(xend_candidates) != 1:
            fail(f"could not uniquely locate trampoline xend before apcount at 0x{apcount:x}")
        xend = xend_candidates[0]
        codepg = (IMAGE_BASE + delta + xend) >> 12

    site_last = IMAGE_BASE + delta + site_offset + len(site) - 1
    site_page = site_last >> 12
    executable = site_page < codepg
    expected_executable = expected == "alive"
    if executable != expected_executable:
        fail(
            f"site final byte page=0x{site_page:x}, CODEPG=0x{codepg:x}, "
            f"executable={executable}; expected executable={expected_executable}"
        )

    print(
        f"PASS: {expected}: DELTA=0x{delta:x}, SITE=0x{site_offset:x}, "
        f"site_bytes={len(site)}, final_site_page=0x{site_page:x}, "
        f"CODEPG=0x{codepg:x}, final_site_byte_executable={int(executable)}"
    )
    print("LIMIT: emitted-layout and source-formula assertion; runtime page-table memory is not read")


if __name__ == "__main__":
    main()
