#!/usr/bin/env python3
"""Local-only regression probe for the frozen bounty ClientHello length quirk.

The inner 24-bit handshake length is deliberately one byte shorter than the
actual TLS record payload. The frozen bounty image is expected to accept it
and send ServerHello because it bounds parsing by the outer record length.
This does not contact 15kb.org.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "target").resolve()
sys.path.insert(0, str(target / "tools"))
from tlsclient import hello_record  # noqa: E402


def main() -> None:
    record = hello_record()
    if record[0] != 22 or record[5] != 1:
        raise SystemExit("FAIL: TLS client did not create a one-record ClientHello")
    body = record[5:]
    declared = int.from_bytes(body[1:4], "big")
    if declared != len(body) - 4:
        raise SystemExit("FAIL: generated ClientHello has inconsistent initial length")

    # Keep the complete valid body and outer TLS record, but lie by one byte in
    # the ClientHello's own 24-bit handshake-message length.
    malformed = body[:1] + (declared - 1).to_bytes(3, "big") + body[4:]
    wire = bytes((22, 3, 1)) + len(malformed).to_bytes(2, "big") + malformed

    with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(wire)
        response = bytearray()
        while len(response) < 7:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

    if len(response) >= 6 and response[0] == 22 and response[5] == 2:
        print("PASS: frozen bounty image accepts a ClientHello whose inner length is one byte short")
        print("INFO: server replied with a TLS ServerHello; only the outer record length bounded parsing")
        print("LIMIT: this confirms malformed-message acceptance, not a key disclosure or memory-safety exploit")
        return

    if len(response) >= 7 and response[0] == 21:
        print(f"FAIL: frozen bounty image rejected the malformed ClientHello with alert {response[6]}")
    else:
        print(f"FAIL: unexpected response to local malformed ClientHello: {bytes(response[:32]).hex()}")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
