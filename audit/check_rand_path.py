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

    require(re.search(r"(?m)^POOLR\s+equ\s+BSS\s*\+", source) is not None,
            "POOLR is no longer stored in BSS")
    require(re.search(r"(?m)^POOLK\s+equ\s+POOLR\s*\+", source) is not None,
            "POOLK is no longer adjacent to the per-processor nonce pool")
    require(re.search(r"(?m)^POOLN\s+equ\s+NV\s*\+\s*64\b", source) is not None,
            "POOLN offset changed; review snapshot/rollback state")
    require(re.search(r"(?m)^POOLFILL\s+equ\s+NV\s*\+\s*68\b", source) is not None,
            "POOLFILL offset changed; review snapshot/rollback state")

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

    boot = re.search(r"(?m)^\s*mov edi, HKS\b.*\n\s*push 22\s*\n\s*pop rcx\s*\n\s*call rand\b", source)
    require(boot is not None, "boot-time 22-qword HKS draw changed")

    # The BSP creates HKS before AP startup. Each AP then receives a private
    # 2 MiB BSS copy, which includes the current RLAST and empty pool counters.
    ap_copy = re.search(
        r"(?ms)^\s*mov esi, BSS\s*\n.*?mov ecx, 0x200000 / 8\s*\n\s*rep movsq\s*\n\s*mov \[rdi\+CPUN-STACK\], ebx",
        source,
    )
    require(ap_copy is not None, "could not verify the per-AP 2 MiB BSS copy")
    require(boot.start() < ap_copy.start(),
            "AP BSS copy no longer follows the BSP's HKS random draw")

    handshake = re.search(r"(?ms)^handshake:.*?(?=^[A-Za-z_][A-Za-z0-9_]*:)", source)
    require(handshake is not None, "could not isolate TLS handshake routine")
    handshake_calls = re.findall(r"(?m)^\s*call\s+rand\b", handshake.group(0))
    require(len(handshake_calls) == 2,
            f"expected two handshake rand calls (X25519 + ServerHello.random), found {len(handshake_calls)}")

    print("PASS: four direct rand call sites mapped (boot, two handshake draws, stock)")
    print("PASS: rand retries CF=0 and rejects adjacent repeated qwords via RLAST")
    print("PASS: stock consumes four qwords per nonce and holds 64 nonce slots")
    print("PASS: RLAST is processor-local BSS state (NV + 208)")
    print("PASS: APs receive a private BSS copy after BSP HKS generation; the initial RLAST is cloned")
    print("PASS: POOLR/POOLK and POOLN/POOLFILL are guest-memory nonce-pool state")
    print("LIMIT: per-processor RLAST is not a global cross-CPU duplicate detector")
    print("LIMIT: static source assertions only; no RDRAND hardware behavior is tested")


if __name__ == "__main__":
    main()
