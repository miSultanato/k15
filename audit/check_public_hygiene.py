#!/usr/bin/env python3
"""Fail if generated secrets or private build artifacts enter the public Git tree.

This checks tracked paths and their checked-out contents. It intentionally does
not attempt broad heuristic secret detection: false positives in public source
are worse than a narrow, auditable guardrail.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath

PEM_BEGIN = b"-----BEGIN "
PRIVATE_KEY = re.compile(
    PEM_BEGIN + rb"(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    + b"|" + PEM_BEGIN + rb"ENCRYPTED PRIVATE KEY-----"
)
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx", ".img", ".bin", ".lst"}


def tracked_paths() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"])
    return [item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item]


def forbidden_path(path: str) -> str | None:
    p = PurePosixPath(path)
    parts = p.parts
    if any(part == "cert" or part.startswith("cert-") or part == "build" or part.startswith("build-") for part in parts[:-1]):
        return "generated build/certificate directory"
    if p.name.lower() == "regs.inc":
        return "generated register constants contain the private scalar"
    if p.suffix.lower() in FORBIDDEN_SUFFIXES:
        return f"private or generated artifact suffix {p.suffix}"
    return None


def main() -> int:
    failures: list[str] = []
    for path in tracked_paths():
        reason = forbidden_path(path)
        if reason:
            failures.append(f"{path}: {reason}")
            continue
        try:
            data = open(path, "rb").read()
        except OSError as exc:
            failures.append(f"{path}: cannot inspect tracked file: {exc}")
            continue
        if PRIVATE_KEY.search(data):
            failures.append(f"{path}: PEM private-key marker")
    if failures:
        print("FAIL: public repository hygiene check found forbidden content:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASS: tracked Git tree contains no generated build/certificate directories,")
    print("      private-key files/PEM markers, disk images, binaries or NASM listings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
