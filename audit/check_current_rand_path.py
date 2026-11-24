#!/usr/bin/env python3
"""Static check of the current upstream RDRAND-to-ECDSA nonce path.

This checks source shape only; it does not test production hardware behavior.
Usage: check_current_rand_path.py COMBINED_SOURCE_ASM
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"FAIL: {message}")


def section(source: str, start: str, end: str) -> str:
    a = source.find(start)
    b = source.find(end, a + len(start))
    require(a >= 0 and b > a, f"cannot isolate {start!r} .. {end!r}")
    return source[a:b]


def main() -> None:
    source = Path(sys.argv[1]).read_text(encoding="utf-8")
    require(re.search(r"(?m)^NPOOL\s+equ\s+64\b", source) is not None,
            "nonce stock size is no longer 64")
    require(re.search(r"(?m)^NV\s+equ\s+BSS\s*\+", source) is not None,
            "per-processor nonce state is not in BSS")
    require(re.search(r"(?m)^RLAST\s+equ\s+NV\s*\+\s*208\b", source) is not None,
            "RLAST offset changed; review processor-local RNG state")

    rand_body = section(source, "rand:   rdrand rax", ".stuck:")
    for fragment in (
        "rdrand rax",
        "jnc rand",
        "cmp rax, [RLAST]",
        "je .stuck",
        "mov [RLAST], rax",
        "stosq",
        "loop rand",
    ):
        require(fragment in rand_body, f"rand routine no longer contains: {fragment}")

    stock = section(source, "stock:  mov ebx", ".all:")
    require(re.search(r"push 4\s+pop rcx\s+call rand", stock) is not None,
            "stock no longer consumes four qwords per nonce")
    calls = re.findall(r"(?m)^\s*call\s+rand\b", source)
    require(len(calls) == 1, f"expected one nonce-stock rand call, found {len(calls)}")

    # The current implementation checks only each qword against the immediately
    # preceding qword. It does not compare complete four-qword nonce tuples.
    require("cmp rax, [RLAST]" in rand_body and "je .stuck" in rand_body,
            "adjacent-qword repetition guard is absent")
    require("POOLK" in stock and "POOLFILL" in stock,
            "nonce stock no longer writes through POOLK/POOLFILL")
    print("PASS: current rand retries RDRAND failure and rejects adjacent repeated qwords")
    print("PASS: RLAST is processor-local BSS state at NV + 208")
    print("PASS: stock obtains four qwords per nonce in a 64-entry pool")
    print("LIMIT: adjacent-qword guard does not prove four-qword nonce uniqueness")
    print("LIMIT: static source check; no RDRAND hardware behavior is tested")


if __name__ == "__main__":
    main()
