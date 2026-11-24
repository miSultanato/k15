#!/usr/bin/env python3
"""Bound the HTTP request-path -> packed SITE response read path.

Usage: check_site_read_path.py TARGET/src/os.asm TARGET/tools/pack.py TARGET/Makefile
This is a targeted static guard, not a proof of the whole assembly program.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + message)


def section(source: str, start: str, end: str) -> str:
    a = source.find(start)
    b = source.find(end, a + len(start))
    require(a >= 0 and b > a, f"cannot isolate source section {start!r} .. {end!r}")
    return source[a:b]


def require_ordered(source: str, fragments: tuple[str, ...], message: str) -> None:
    offset = 0
    for fragment in fragments:
        found = source.find(fragment, offset)
        require(found >= 0, f"{message}: missing or out-of-order {fragment!r}")
        offset = found + len(fragment)


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(__doc__.strip())
    asm_path, pack_path, makefile_path = map(Path, sys.argv[1:])
    asm = asm_path.read_text(encoding="utf-8")
    pack = pack_path.read_text(encoding="utf-8")
    makefile = makefile_path.read_text(encoding="utf-8")

    lookup = section(asm, ".pr:    and eax, PT_MASK", ".other: xor edx, edx")
    require_ordered(
        lookup,
        (
            "and eax, PT_MASK",
            "mov ecx, [SITE+rax*8+4]",
            "jrcxz .nf",
            "cmp [SITE+rax*8], edi",
            "cmp [SITE+rcx+2], dx",
            "lea edi, [SITE+rcx+4]",
            "repe cmpsb",
            ".hit:   movzx eax, word [SITE+rcx]",
        ),
        "request path lookup",
    )
    require("inc eax\n        jmp .pr" in lookup,
            "path hash collision probing is no longer linear and mask-bounded")

    geom = section(asm, "geom:   pushad", ".pe:    mov r9d")
    require_ordered(
        geom,
        (
            "movzx eax, word [rbp+C_AS]",
            "mov esi, eax",
            "and esi, 0x7FFF",
            "shl esi, 4",
            "add esi, SITE + AT_OFF",
            "mov edx, [rsi]",
            "add edx, SITE",
            "mov [TXBLOB], edx",
            "mov eax, [rsi+4]",
        ),
        "response-index and blob-offset calculation",
    )
    require("mov [TXL], eax" in geom and "mov [TXEND], eax" in geom,
            "response lengths no longer determine a bounded TX interval")

    pick = section(asm, "pick:   pushad", ".line:  mov esi, r10d")
    require_ordered(
        pick,
        (
            "mov ebp, eax",
            "shl eax, 4",
            "mov bl, [SITE+AT_OFF+rax+12]",
            "add ebp, 4",
            "inc ebp",
            "lea eax, [rbp+1]",
            "shl eax, 4",
            "mov edi, [SITE+AT_OFF+rax]",
            "add edi, SITE + ETAG_AT",
        ),
        "prepacked response-form selection",
    )

    require(re.search(r"\bSITE\s*-\s*", asm) is None,
            "assembly contains a SITE-relative negative-base expression")
    wx = section(asm, "%ifdef WXTEST", "%endif")
    require("SITE + SITE_LEN - 1" in wx,
            "expected page-permission probe is no longer isolated under WXTEST")
    require(asm.count("SITE + SITE_LEN - 1") == 2,
            "SITE end-byte write/execute probe escaped its test-only block")

    require("MAX_SITE = 768 << 20" in pack,
            "packer site-size bound changed")
    require("MAX_FILE = 1 << 30" in pack,
            "packer response-size bound changed")
    require("while slots < 2 * len(paths):" in pack,
            "path table is no longer at most half full")
    require("if len(responses) > 0x7FFF:" in pack,
            "packer response-index bound changed")
    require("if len(data) > MAX_SITE:" in pack,
            "packer no longer enforces MAX_SITE")
    require("recs_at = at + 16 * len(responses)" in pack and
            "blobs_at = recs_at + len(recs)" in pack,
            "packed response/path/blob layout changed")
    require("PT_MASK equ {slots - 1}" in pack and
            "AT_OFF equ {at}" in pack and
            "%assign SITE_LEN {len(data)}" in pack,
            "packer no longer emits the table bounds consumed by os.asm")

    require("$(if $(WXTEST),-DWXTEST=$(WXTEST),)" in makefile,
            "Makefile no longer treats WXTEST as an optional build define")
    require("all: $(B)/disk.img" in makefile,
            "default image build target changed; re-review WXTEST build selection")

    print("PASS: request paths select only exact, packer-generated path records")
    print("PASS: response IDs are masked and resolve through fixed 16-byte SITE entries")
    print("PASS: blob pointers are SITE + packer-generated offsets and lengths")
    print("PASS: compression/304 selection only chooses prepacked response variants")
    print("PASS: path table is <=50% full; response IDs <=32,767; SITE <=768 MiB")
    print("PASS: SITE end-byte write/execute probe is isolated under optional WXTEST")
    print("PASS: no request-controlled SITE-to-preceding-memory read path found")


if __name__ == "__main__":
    main()
