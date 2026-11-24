#!/usr/bin/env python3
"""Static audit of the private-scalar read path in the pinned k15 source.

This checks source structure and the compile-time curve program. It does not
inspect a production image, infer the secret scalar, or contact the live host.
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
    require(a >= 0 and b > a, f"cannot isolate source section {start!r} .. {end!r}")
    return source[a:b]


def main() -> None:
    asm_path = Path(sys.argv[1] if len(sys.argv) > 1 else "target/src/os.asm")
    ec_path = Path(sys.argv[2] if len(sys.argv) > 2 else "target/tools/ec.py")
    asm = asm_path.read_text(encoding="utf-8")
    ec = ec_path.read_text(encoding="utf-8")

    require(re.search(r"(?m)^REGS\s+equ\s+BSS\s*\+\s*0x0E400\b", asm) is not None,
            "curve register bank base changed")
    require(re.search(r"(?m)^R_D\s+equ\s+REGS\s*\+\s*14\s*\*\s*32\b", asm) is not None,
            "private scalar register is no longer register 14")
    r_d_refs = [(i, line.strip()) for i, line in enumerate(asm.splitlines(), 1)
                if re.search(r"\bR_D\b", line)]
    require(len(r_d_refs) == 2 and "equ" in r_d_refs[0][1] and "mov edi, R_D" in r_d_refs[1][1],
            f"unexpected direct R_D references: {r_d_refs}")

    init = section(asm, "mov edi, R_D", "mov edi, TABE")
    require(re.search(r"mov edi, R_D\s+mov cl, 8\s+rep movsq", init) is not None,
            "R_D initialization is no longer a fixed eight-qword copy")

    reg = section(asm, ".reg:", "; (T1 = 1 / Z")
    for fragment in ("and eax, 15", "shl eax, 5", "add eax, REGS", "stosd"):
        require(fragment in reg, f"register decoder lost bound/mapping: {fragment}")

    vm = section(asm, "vm:     mov edi, [rsi]", "HOT 0xF9FFC3FE")
    for fragment in ("mov ebx, [rsi+8]", "mov ecx, [rsi+12]", "mov esi, [rsi+4]",
                     "add rsi, 16", "jmp vm"):
        require(fragment in vm, f"VM instruction decoding changed: {fragment}")

    sign = section(asm, "sign:   pushad", "; rand:")
    require(re.search(r"mov esi, X_SIGN\s+call vm", sign) is not None,
            "sign routine no longer invokes the fixed X_SIGN program")
    require(len(re.findall(r"\bX_SIGN\b", asm)) == 1,
            "X_SIGN has unexpected additional source references")

    programs = re.findall(r'(?ms)^([A-Z0-9_]+)\s*=\s*asm\("""(.*?)""")', ec)
    require(programs, "no compile-time curve programs found in tools/ec.py")
    d_users = []
    for name, body in programs:
        code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        if re.search(r"\bD\b", code):
            d_users.append((name, re.findall(r"(?m)^\s*.*\bD\b.*$", code)))
    require([name for name, _ in d_users] == ["SIGN"],
            f"unexpected curve programs reference register D: {d_users}")
    sign_body = dict(programs)["SIGN"]
    sign_code = "\n".join(line.split("#", 1)[0] for line in sign_body.splitlines())
    require(re.findall(r"(?m)^\s*T0\s*=\s*X\s*\*\s*D\s*$", sign_code) != [],
            "SIGN no longer has its single explicit X * D operation")
    require(len(re.findall(r"\bD\b", sign_code)) == 1,
            "SIGN has more than one D operand")

    print("PASS: R_D is register 14 in the per-processor BSS register bank")
    print("PASS: only one direct R_D source reference initializes the register")
    print("PASS: VM register decoding masks indices to 0..15 before address formation")
    print("PASS: sign invokes the fixed X_SIGN curve program")
    print("PASS: only the compile-time SIGN program reads D, once, as X * D")
    print("LIMIT: static source audit; does not inspect runtime state or prove all CPU behavior")


if __name__ == "__main__":
    main()
