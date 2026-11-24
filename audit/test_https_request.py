#!/usr/bin/env python3
"""Probe HTTP request parsing inside TLS application data on local QEMU.

This deliberately uses the HTTPS listener (host port 8443), not cleartext
port 80, because the audited request parser handles decrypted TLS records.
Usage: test_https_request.py TARGET
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: test_https_request.py TARGET")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
import tlsclient  # noqa: E402

HOST, PORT = "127.0.0.1", 8443
HOST_HEADER = b"Host: " + tlsclient.NAME.encode() + b"\r\n"


def request(label: str, wire: bytes) -> bytes:
    raw = socket.create_connection((HOST, PORT), timeout=5)
    raw.settimeout(3)
    tls = tlsclient.context().wrap_socket(raw, server_hostname=tlsclient.NAME)
    tls.settimeout(2)
    response = bytearray()
    try:
        tls.sendall(wire)
        while b"\r\n\r\n" not in response and len(response) < 8192:
            try:
                chunk = tls.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            if not chunk:
                break
            response.extend(chunk)
    finally:
        try:
            tls.close()
        except OSError:
            pass
    if response:
        status = response.split(b"\r\n", 1)[0]
        print(f"OBSERVED: HTTPS {label}: {status.decode('ascii', 'replace')}")
    else:
        print(f"OBSERVED: HTTPS {label}: no HTTP response before timeout/close")
    return bytes(response)


def main() -> None:
    normal = request(
        "GET control",
        b"GET / HTTP/1.1\r\n" + HOST_HEADER + b"Connection: close\r\n\r\n",
    )
    if not normal.startswith(b"HTTP/1.1 200"):
        raise SystemExit("FAIL: valid HTTPS GET control did not return HTTP 200")

    request(
        "lowercase get",
        b"get / HTTP/1.1\r\n" + HOST_HEADER + b"Connection: close\r\n\r\n",
    )
    request(
        "unknown FOO method",
        b"FOO / HTTP/1.1\r\n" + HOST_HEADER + b"Connection: close\r\n\r\n",
    )
    request(
        "GET without Host",
        b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
    )


if __name__ == "__main__":
    main()
