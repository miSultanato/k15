#!/usr/bin/env python3
"""Read the live x86-64 PTE for the final byte of a synthetic SITE in local QEMU.

No guest memory is modified. QEMU is stopped after CR3 becomes nonzero; the
probe walks the guest's physical page tables through the QEMU HMP monitor.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MASK = 0x000FFFFFFFFFF000


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


class QMP:
    def __init__(self, path: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic() + 20
        while True:
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    fail("QMP socket did not become ready")
                time.sleep(0.1)
        self.file = self.sock.makefile("rwb", buffering=0)
        self._read()
        self.command("qmp_capabilities")

    def _read(self):
        while True:
            line = self.file.readline()
            if not line:
                fail("QMP closed unexpectedly")
            obj = json.loads(line)
            if "return" in obj or "error" in obj or "QMP" in obj:
                return obj

    def command(self, name: str, arguments: dict | None = None):
        payload = {"execute": name}
        if arguments is not None:
            payload["arguments"] = arguments
        self.file.write(json.dumps(payload).encode() + b"\r\n")
        result = self._read()
        if "error" in result:
            fail(f"QMP {name}: {result['error']}")
        return result.get("return")

    def hmp(self, command: str) -> str:
        return self.command("human-monitor-command", {"command-line": command})

    def close(self):
        self.file.close()
        self.sock.close()


def read_phys(qmp: QMP, address: int) -> int:
    output = qmp.hmp(f"xp /1gx 0x{address:x}")
    values = re.findall(r"0x([0-9a-fA-F]{1,16})", output)
    if not values:
        fail(f"could not parse physical read at 0x{address:x}: {output!r}")
    return int(values[-1], 16)


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"alive", "reset"}:
        fail("usage: probe_wx_pte.py TARGET alive|reset")
    root = Path(sys.argv[1]).resolve()
    build = root / "build-wx-pte"
    image = (build / "os.bin").read_bytes()
    site = (build / "site.bin").read_bytes()
    if not site or image[-len(site):] != site:
        fail("synthetic SITE is not the exact non-empty image tail")
    delta_file = build / "delta"
    delta = 0
    if delta_file.exists():
        match = re.fullmatch(r"-DDELTA=(\d+)\s*", delta_file.read_text(encoding="ascii"))
        if not match:
            fail("could not parse DELTA build definition")
        delta = int(match.group(1))
    low = (((0x110000 + len(site) + 0x1FFFFF) >> 21) << 21) - 0x200000
    expected_cr3 = 0x420000 + low  # PML4 = VQ + 0x20000; VQ = 0x400000 + LOW
    virtual = 0x100000 + delta + len(image) - 1
    if virtual >= 0x200000:
        fail(f"target 0x{virtual:x} is outside PT0's first 2 MiB mapping")

    with tempfile.TemporaryDirectory(prefix="k15-wx-pte-") as tmp:
        qmp_path = str(Path(tmp) / "qmp.sock")
        command = [
            "qemu-system-x86_64", "-nodefaults", "-display", "none",
            "-no-reboot", "-machine", "q35", "-smp", "1", "-cpu", "max",
            "-m", "256", "-monitor", "none", "-serial", "none",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-drive", f"file={build / 'disk.img'},format=raw,if=none,id=d0,snapshot=on",
            "-netdev", "user,id=n0",
            "-device", "pcie-root-port,id=rp1,chassis=1",
            "-device", "virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile=",
            "-device", "pcie-root-port,id=rp2,chassis=2",
            "-device", "virtio-scsi-pci,bus=rp2",
            "-device", "scsi-hd,drive=d0",
        ]
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        qmp = None
        try:
            qmp = QMP(qmp_path)
            deadline = time.monotonic() + 20
            registers = ""
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    fail("QEMU exited before page tables could be inspected")
                registers = qmp.hmp("info registers")
                match = re.search(r"CR3=([0-9a-fA-F]+)", registers)
                if match and (int(match.group(1), 16) & MASK) == expected_cr3:
                    break
                time.sleep(0.1)
            else:
                fail(f"guest did not install expected CR3 0x{expected_cr3:x} within 20 seconds")
            qmp.command("stop")
            cr3_match = re.search(r"CR3=([0-9a-fA-F]+)", qmp.hmp("info registers"))
            if not cr3_match:
                fail("could not read CR3 from stopped guest")
            cr3 = int(cr3_match.group(1), 16) & MASK

            indexes = ((virtual >> 39) & 0x1FF, (virtual >> 30) & 0x1FF,
                       (virtual >> 21) & 0x1FF, (virtual >> 12) & 0x1FF)
            table = cr3
            entries = []
            for level, index in zip(("PML4", "PDPT", "PD", "PT"), indexes):
                entry = read_phys(qmp, table + index * 8)
                entries.append((level, table + index * 8, entry))
                if not entry & 1:
                    fail(f"{level}[{index}] is not present: 0x{entry:016x}")
                if level != "PT":
                    if entry & (1 << 7):
                        fail(f"unexpected large-page entry at {level}")
                    table = entry & MASK
            pte = entries[-1][2]
            nx = bool(pte & (1 << 63))
            writable = bool(pte & 2)
            expected_nx = sys.argv[2] == "reset"
            print(f"CR3=0x{cr3:x} VA=0x{virtual:x} DELTA=0x{delta:x} final_SITE_byte=0x{site[-1]:02x}")
            for level, address, entry in entries:
                print(f"{level} entry @ 0x{address:x} = 0x{entry:016x}")
            print(f"RESULT: present=1 writable={int(writable)} NX={int(nx)}")
            print("PASS: live PTE matches expected NX state" if nx == expected_nx
                  else "FAIL: live PTE NX state differs from expected")
            if nx != expected_nx or writable:
                if writable:
                    print("FAIL: SITE PTE is writable; expected read-only")
                raise SystemExit(1)
        finally:
            if qmp is not None:
                try:
                    qmp.command("quit")
                except Exception:
                    pass
                qmp.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
