#!/usr/bin/env python3
"""Exercise the boot sector's E820 SMAP-signature gate in a tiny 16-bit emulator.

The frozen and fixed boot sectors are assembled unchanged. Execution starts at
the E820 loop, with BIOS INT 15h responses supplied by Unicorn; no guest kernel,
network, production host, or disk image is involved.

Usage: test_e820_signature.py TARGET frozen|fixed
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_16
from unicorn.x86_const import UC_X86_REG_DI, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EFLAGS, UC_X86_REG_IP

ORG = 0x7C00
MMAP_FIRST = 0x6004
SMAP = 0x534D4150
WRONG_SIGNATURE = 0xDEADBEEF


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def assemble(root: Path, temp: Path) -> tuple[bytes, int, int]:
    listing = temp / "boot.lst"
    binary = temp / "boot.bin"
    subprocess.run(
        ["nasm", "-f", "bin", "-l", str(listing), "-o", str(binary), str(root / "src/boot.asm")],
        check=True,
    )
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()

    def label_address(name: str) -> int:
        for line in lines:
            if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}:", line):
                continue
            match = re.match(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+", line)
            if match:
                address = int(match.group(1), 16)
                return address - ORG if address >= ORG else address
        fail(f"NASM listing does not expose label {name}")
        raise AssertionError

    return binary.read_bytes(), label_address(".e820"), label_address(".done")


def run_response(boot: bytes, e820_offset: int, done_offset: int, signature: int) -> int:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x200000)
    uc.mem_write(ORG, boot)
    uc.reg_write(UC_X86_REG_DI, MMAP_FIRST)
    uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
    uc.reg_write(UC_X86_REG_IP, e820_offset)

    def bios_interrupt(machine: Uc, interrupt: int, _user_data: object) -> None:
        if interrupt != 0x15:
            fail(f"unexpected interrupt 0x{interrupt:x}")
        machine.reg_write(UC_X86_REG_EAX, signature)
        machine.reg_write(UC_X86_REG_EBX, 0)
        flags = machine.reg_read(UC_X86_REG_EFLAGS)
        machine.reg_write(UC_X86_REG_EFLAGS, flags & ~1)  # BIOS call succeeded

    uc.hook_add(UC_HOOK_INTR, bios_interrupt)
    uc.emu_start(ORG + e820_offset, ORG + done_offset, count=100)
    return uc.reg_read(UC_X86_REG_DI)


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"frozen", "fixed"}:
        fail("usage: test_e820_signature.py TARGET frozen|fixed")
    root = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="k15-e820-") as directory:
        boot, e820, done = assemble(root, Path(directory))
        accepted = run_response(boot, e820, done, SMAP)
        rejected = run_response(boot, e820, done, WRONG_SIGNATURE)

    if accepted != MMAP_FIRST + 24:
        fail(f"valid SMAP response was not accepted: DI=0x{accepted:04x}")
    expected_wrong = MMAP_FIRST if sys.argv[2] == "fixed" else MMAP_FIRST + 24
    if rejected != expected_wrong:
        fail(
            f"{sys.argv[2]} wrong-signature behavior: DI=0x{rejected:04x}, "
            f"expected 0x{expected_wrong:04x}"
        )

    print(f"PASS: {sys.argv[2]} accepts a valid SMAP response (DI=0x{accepted:04x})")
    if sys.argv[2] == "fixed":
        print("PASS: fixed boot sector rejects a successful INT 15h response with a wrong EAX signature")
    else:
        print("CONFIRMED: frozen boot sector counts a wrong-signature response as a memory-map entry")
    print("LIMIT: deterministic 16-bit E820-path emulation; no real BIOS compatibility claim")


if __name__ == "__main__":
    main()
