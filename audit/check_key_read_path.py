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
    gen_path = Path(sys.argv[3] if len(sys.argv) > 3 else "target/tools/gen.py")
    asm = asm_path.read_text(encoding="utf-8")
    ec = ec_path.read_text(encoding="utf-8")
    gen = gen_path.read_text(encoding="utf-8")

                if re.search(r"\bREGS\b", line)
            "curve register bank base changed")
    require(re.search(r"(?m)^R_D\s+equ\s+REGS\s*\+\s*14\s*\*\s*32\b", asm) is not None,
            "private scalar register is no longer register 14")
    r_d_refs = [(i, line.strip()) for i, line in enumerate(asm.splitlines(), 1)
                if re.search(r"\bR_D\b", line)]
    require(len(r_d_refs) == 2 and "equ" in r_d_refs[0][1] and "mov edi, R_D" in r_d_refs[1][1],
            f"unexpected direct R_D references: {r_d_refs}")

    regs_ops = [line.strip().split(";", 1)[0].strip()
                for line in asm.splitlines()
                if re.search(r"\\bREGS\\b", line)
                and "equ" not in line
                and not line.lstrip().startswith(";")]
    require(regs_ops == ["mov edi, REGS", "mov edi, REGS", "add eax, REGS"],
            f"unexpected direct register-bank address operations: {regs_ops}")

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

    select = section(asm, "select: mov edi, REGS", "HOT 0x40F70000")
    for fragment in ("movdqa xmm4, [rsi]", "por xmm4, [rdi+rax]",
                     "movdqa [rdi+rax], xmm4", "add eax, 16",
                     "cmp eax, ecx", "jb .c"):
        require(fragment in select, f"table selection access changed: {fragment}")

    # The only select path is through comb. Its callers use fixed entry widths:
    # 96 bytes for Edwards25519 and 64 bytes for P-256, both far below R_D at +448.
    require(asm.count("call select") == 1,
            "select has an unexpected additional caller")
    xdh = section(asm, "xdh:    pushad", "; sign:")
    stock = section(asm, "stock:  mov ebx", ".all:")
    require(re.search(r"push 96\s+pop rcx", xdh) is not None,
            "X25519 table entry width is no longer fixed at 96 bytes")
    require(re.search(r"push 64\s+pop rcx", stock) is not None,
            "P-256 table entry width is no longer fixed at 64 bytes")
    require("call comb" in xdh and "call comb" in stock,
            "table selection no longer flows through the bounded comb callers")

    sign = section(asm, "sign:   pushad", "; rand:")
    require(re.search(r"mov esi, X_SIGN\s+call vm", sign) is not None,
            "sign routine no longer invokes the fixed X_SIGN program")
    require(len(re.findall(r"\bX_SIGN\b", asm)) == 1,
            "X_SIGN has unexpected additional source references")

    programs = []
    for match in re.finditer(r"(?m)^([A-Z0-9_]+)\s*=\s*asm\(", ec):
        opening = ec.find('"""', match.end())
        closing = ec.find('"""', opening + 3)
        require(opening >= 0 and closing > opening,
                f"cannot read triple-quoted body for {match.group(1)}")
        programs.append((match.group(1), ec[opening + 3:closing]))
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
    print("PASS: all direct REGS address operations are enumerated and bounded")
    print("PASS: VM register decoding masks indices to 0..15 before address formation")
    print("PASS: sign invokes the fixed X_SIGN curve program")
    require("for name, prog in curve.PROGRAMS.items()" in gen and
            "db(name, prog)" in gen and "ec.inc" in gen,
            "tools/gen.py no longer emits ec.inc from tools/ec.py program definitions")

    print("PASS: only the compile-time SIGN program reads D, once, as X * D")
    print("PASS: table selection touches only fixed 64/96-byte prefixes of REGS, not D at +448")
    print("PASS: tools/gen.py emits the VM program image from the checked tools/ec.py definitions")
    print("LIMIT: static source audit; does not inspect runtime state or prove all CPU behavior")


if __name__ == "__main__":
    main()
