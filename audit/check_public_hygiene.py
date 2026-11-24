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

PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]+\r?\n)+"
    rb"-----END (?P=label)-----"
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


def history_objects() -> list[tuple[str, str, bytes]]:
    """Return reachable historical blobs with their first known path."""
    listing = subprocess.check_output(["git", "rev-list", "--objects", "--all"])
    entries: list[tuple[str, str]] = []
    for line in listing.splitlines():
        if not line:
            continue
        sha, sep, raw_path = line.partition(b" ")
        if len(sha) != 40:
            continue
        path = raw_path.decode("utf-8", "surrogateescape") if sep else ""
        entries.append((sha.decode("ascii"), path))
    if not entries:
        return []

    request = b"".join(sha.encode("ascii") + b"\n" for sha, _ in entries)
    output = subprocess.check_output(["git", "cat-file", "--batch"], input=request)
    offset = 0
    blobs: list[tuple[str, str, bytes]] = []
    for sha, path in entries:
        line_end = output.find(b"\n", offset)
        if line_end < 0:
            raise RuntimeError("truncated git cat-file --batch header")
        header = output[offset:line_end].split()
        offset = line_end + 1
        if len(header) != 3:
            raise RuntimeError(f"unexpected git cat-file header for {sha}")
        object_type = header[1]
        size = int(header[2])
        data = output[offset : offset + size]
        if len(data) != size:
            raise RuntimeError(f"truncated git object {sha}")
        offset += size
        if offset >= len(output) or output[offset : offset + 1] != b"\n":
            raise RuntimeError(f"missing git cat-file separator for {sha}")
        offset += 1
        if object_type == b"blob":
            blobs.append((sha, path, data))
    return blobs


def main() -> int:
    args = sys.argv[1:]
    history = "--history" in args
    if any(arg != "--history" for arg in args):
        raise SystemExit("usage: check_public_hygiene.py [--history]")

    failures: list[str] = []
    for path in tracked_paths():
        reason = forbidden_path(path)
        if reason:
            failures.append(f"working tree {path}: {reason}")
            continue
        try:
            data = open(path, "rb").read()
        except OSError as exc:
            failures.append(f"working tree {path}: cannot inspect tracked file: {exc}")
            continue
        if PRIVATE_KEY.search(data):
            failures.append(f"working tree {path}: complete PEM private-key block")

    if history:
        for sha, path, data in history_objects():
            reason = forbidden_path(path) if path else None
            if reason:
                failures.append(f"history {sha[:12]} {path}: {reason}")
            if PRIVATE_KEY.search(data):
                failures.append(f"history {sha[:12]} {path or '(path unavailable)'}: PEM private-key marker")

    if failures:
        print("FAIL: public repository hygiene check found forbidden content:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASS: working tree contains no generated build/certificate directories,")
    print("      private-key files/PEM markers, disk images, binaries or NASM listings.")
    if history:
        print("PASS: all reachable Git history contains no forbidden paths or complete PEM private-key blocks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
