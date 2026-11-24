#!/usr/bin/env python3
"""Force and inspect a TLS 1.3 HelloRetryRequest on a local QEMU guest.

OpenSSL offers secp384r1 first and X25519 second. A local TCP relay captures
both directions so the test asserts the actual second ClientHello and server
dummy ChangeCipherSpec count without modifying TLS bytes.

Usage: test_hrr_second_clienthello.py TARGET none|some
"""
from __future__ import annotations

import select
import socket
import subprocess
import sys
import threading
from pathlib import Path

HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def parse_records(data: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 5 <= len(data):
        size = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if offset + 5 + size > len(data):
            break
        result.append((data[offset], data[offset + 5 : offset + 5 + size]))
        offset += 5 + size
    return result


def parse_handshakes(items: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    stream = b"".join(payload for kind, payload in items if kind == 22)
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(stream):
        size = int.from_bytes(stream[offset + 1 : offset + 4], "big")
        if offset + 4 + size > len(stream):
            break
        result.append((stream[offset], stream[offset + 4 : offset + 4 + size]))
        offset += 4 + size
    return result


class Relay:
    def __init__(self) -> None:
        self.client_bytes = bytearray()
        self.server_bytes = bytearray()
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 8444))
        self.listener.listen(1)
        self.listener.settimeout(12)

    def run(self) -> None:
        try:
            client, _ = self.listener.accept()
            with client, socket.create_connection(("127.0.0.1", 8443), timeout=5) as upstream:
                client.setblocking(False)
                upstream.setblocking(False)
                while True:
                    readable, _, _ = select.select([client, upstream], [], [], 12)
                    if not readable:
                        break
                    for source in readable:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        if source is client:
                            self.client_bytes.extend(chunk)
                            upstream.sendall(chunk)
                        else:
                            self.server_bytes.extend(chunk)
                            client.sendall(chunk)
        except BaseException as exc:
            self.error = exc
        finally:
            self.listener.close()
            self.ready.set()


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"none", "some"}:
        fail("usage: test_hrr_second_clienthello.py TARGET none|some")
    if not Path(sys.argv[1]).is_dir():
        fail(f"target directory does not exist: {sys.argv[1]}")

    relay = Relay()
    thread = threading.Thread(target=relay.run, daemon=True)
    thread.start()
    command = [
        "openssl", "s_client",
        "-connect", "127.0.0.1:8444",
        "-tls1_3",
        "-groups", "secp384r1:x25519",
        "-servername", "localhost",
        "-brief",
    ]
    try:
        client = subprocess.run(
            command, input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=18, check=False,
        )
    except subprocess.TimeoutExpired:
        fail("OpenSSL client timed out during local HRR handshake")
    thread.join(timeout=5)
    if not relay.ready.is_set():
        fail("local TLS relay did not finish capturing the handshake")
    if relay.error is not None:
        fail(f"local TLS relay failed: {relay.error}")

    sent = parse_records(bytes(relay.client_bytes))
    received = parse_records(bytes(relay.server_bytes))
    client_messages = parse_handshakes(sent)
    server_messages = parse_handshakes(received)
    client_hellos = sum(kind == 1 for kind, _ in client_messages)
    server_hellos = sum(kind == 2 for kind, _ in server_messages)
    hrr = any(
        kind == 2 and len(body) >= 34 and body[2:34] == HRR_RANDOM
        for kind, body in server_messages
    )
    server_ccs = sum(kind == 20 for kind, _ in received)
    output = client.stdout.decode("utf-8", errors="replace")
    print(output.strip())
    print(
        f"HRR capture: client_hellos={client_hellos}, hrr={hrr}, "
        f"server_hellos={server_hellos}, server_ccs={server_ccs}, "
        f"openssl_exit={client.returncode}"
    )

    if not hrr or client_hellos < 2:
        fail("OpenSSL did not complete the intended HRR -> second ClientHello path")
    if client.returncode != 0 or "Protocol version: TLSv1.3" not in output:
        fail("OpenSSL TLS 1.3 handshake did not complete")
    if server_hellos < 2:
        fail("server did not send a final ServerHello after HRR")
    expected = sys.argv[2]
    if expected == "none" and server_ccs != 0:
        fail(f"expected no server dummy CCS, observed {server_ccs}")
    if expected == "some" and server_ccs == 0:
        fail("expected server dummy CCS on the HRR handshake")
    print(f"PASS: completed HRR second-ClientHello handshake; server CCS expectation={expected}")


if __name__ == "__main__":
    main()
