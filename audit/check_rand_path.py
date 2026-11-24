#!/usr/bin/env python3
"""Static guard for the frozen k15 RDRAND/nonce call path.

This is a source-shape assertion, not a hardware RNG test. It deliberately
runs against the pinned bounty source checked out by bounded-audit.yml.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "target/src/os.asm")
    source = path.read_text(encoding="utf-8")

    direct_calls = re.findall(r"^\s*call\s+rand\b", source, re.MULTILINE)
    require(len(direct_calls) == 4, f"expected 4 direct call rand sites, found {len(direct_calls)}")

    require(re.search(r"(?m)^NPOOL\s+equ\s+64\b", source) is not None,
            "nonce stock size is no longer 64")
    require(re.search(r"(?m)^NV\s+equ\s+BSS\s*\+", source) is not None,
            "per-processor NV state is not based in BSS")
    require(re.search(r"(?m)^RLAST\s+equ\s+NV\s*\+\s*208\b", source) is not None,
            "RLAST offset changed; review per-processor health-check state")

    rand_match = re.search(r"(?ms)^rand:\s*(.*?)^\.stuck:", source)
    require(rand_match is not None, "could not isolate rand routine")
    rand_body = rand_match.group(1)
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

    stock_match = re.search(r"(?ms)^stock:\s*(.*?)^binv:", source)
    require(stock_match is not None, "could not isolate stock routine")
    stock_body = stock_match.group(1)
    require(re.search(r"(?s)push 4\s+pop rcx\s+call rand", stock_body) is not None,
            "stock no longer consumes four qwords per nonce")

    boot = re.search(r"(?s)mov edi, HKS\s+push 22\s+pop rcx\s+call rand", source)
    require(boot is not None, "boot-time 22-qword HKS draw changed")

    handshake = re.search(r"(?ms)^\.has:.*?^\.alert:", source)
    require(handshake is not None, "could not isolate TLS handshake path")
    handshake_calls = re.findall(r"(?m)^\s*call\s+rand\b", handshake.group(0))
    require(len(handshake_calls) == 2,
            f"expected two handshake rand calls (X25519 + ServerHello.random), found {len(handshake_calls)}")

    print("PASS: four direct rand call sites mapped (boot, two handshake draws, stock)")
    print("PASS: rand retries CF=0 and rejects adjacent repeated qwords via RLAST")
    print("PASS: stock consumes four qwords per nonce and holds 64 nonce slots")
    print("PASS: RLAST is processor-local BSS state (NV + 208)")
    print("LIMIT: static source assertions only; no RDRAND hardware behavior is tested")


if __name__ == "__main__":
    main()
