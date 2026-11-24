#!/usr/bin/env python3
"""Local-only TLS 1.3 negative-record tests against the QEMU guest on loopback.

Checks whether a corrupted client Finished is ignored before authenticated app
traffic, and whether a bad application-record tag is fatal or silently ignored.
Requires the synthetic certificate and QEMU listener created by tools/vm.sh.
"""
from __future__ import annotations

import socket
import ssl
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: test_tls_record_rejection.py TARGET")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
import tlsclient  # noqa: E402

HOST = "127.0.0.1"
PORT = 8443
REQUEST = (
    f"GET / HTTP/1.1\r\nHost: {tlsclient.NAME}\r\n"
    "Connection: close\r\n\r\n"
).encode("ascii")


def records(wire: bytes) -> list[tuple[int, int, int]]:
    found = []
    offset = 0
    while offset < len(wire):
        if len(wire) - offset < 5:
            raise RuntimeError("truncated TLS record header from client")
        length = int.from_bytes(wire[offset + 3 : offset + 5], "big")
        end = offset + 5 + length
        if end > len(wire):
            raise RuntimeError("truncated TLS record body from client")
        found.append((wire[offset], offset, end))
        offset = end
    return found


def mutate_last_application_record(wire: bytes) -> bytes:
    app = [item for item in records(wire) if item[0] == 23]
    if not app:
        raise RuntimeError("no TLS application_data record found to corrupt")
    _, _, end = app[-1]
    changed = bytearray(wire)
    changed[end - 1] ^= 1
    return bytes(changed)


def connect_and_handshake():
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(3)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    ctx = tlsclient.context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    tls = ctx.wrap_bio(inc, out, server_hostname=tlsclient.NAME)

    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            pending = out.read()
            if pending:
                sock.sendall(pending)
            incoming = sock.recv(65536)
            if not incoming:
                raise ConnectionError("guest closed during TLS handshake")
            inc.write(incoming)

    # The handshake is complete from OpenSSL's perspective. Its final outbound
    # flight contains the client Finished; retain it so the test can alter only
    # the wire record, without changing the client's application traffic keys.
    finished = out.read()
    if not any(kind == 23 for kind, _, _ in records(finished)):
        raise RuntimeError("client Finished flight has no encrypted TLS record")
    return sock, inc, out, tls, finished


def read_http(sock: socket.socket, inc: ssl.MemoryBIO, tls: ssl.SSLObject) -> bytes:
    response = bytearray()
    while len(response) < 131072:
        try:
            plain = tls.read(16384)
            if plain:
                response.extend(plain)
                marker = response.find(b"\r\n\r\n")
                if marker >= 0:
                    headers = bytes(response[:marker]).lower()
                    for line in headers.split(b"\r\n"):
                        if line.startswith(b"content-length:"):
                            try:
                                wanted = marker + 4 + int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                wanted = 0
                            if wanted and len(response) >= wanted:
                                return bytes(response)
        except ssl.SSLWantReadError:
            try:
                incoming = sock.recv(65536)
            except socket.timeout:
                break
            if not incoming:
                break
            inc.write(incoming)
        except ssl.SSLZeroReturnError:
            break
    return bytes(response)


def send_application(tls: ssl.SSLObject, out: ssl.MemoryBIO, sock: socket.socket) -> bytes:
    tls.write(REQUEST)
    wire = out.read()
    if not wire:
        raise RuntimeError("OpenSSL produced no application record")
    return wire


def test_corrupt_client_finished() -> None:
    sock, inc, out, tls, finished = connect_and_handshake()
    try:
        sock.sendall(mutate_last_application_record(finished))
        app = send_application(tls, out, sock)
        sock.sendall(app)
        response = read_http(sock, inc, tls)
        if not response.startswith(b"HTTP/1."):
            raise SystemExit(
                "FAIL: after corrupted client Finished, no HTTP response; "
                f"received={response[:80]!r}"
            )
        print("PASS: server processed application data after a corrupted client Finished")
    finally:
        sock.close()


def test_bad_application_tag() -> None:
    sock, inc, out, tls, finished = connect_and_handshake()
    try:
        sock.sendall(finished)
        app = send_application(tls, out, sock)
        # Send a damaged copy followed by the original same-sequence record.
        # If the bad tag is silently ignored, the valid record can still be
        # authenticated with the unchanged TLS record sequence number.
        sock.sendall(mutate_last_application_record(app))
        sock.sendall(app)
        response = read_http(sock, inc, tls)
        if not response.startswith(b"HTTP/1."):
            raise SystemExit(
                "FAIL: valid same-sequence app record after bad tag was not processed; "
                f"received={response[:80]!r}"
            )
        print("PASS: server ignored a bad AEAD tag and processed the valid same-sequence record")
    finally:
        sock.close()


if __name__ == "__main__":
    test_corrupt_client_finished()
    test_bad_application_tag()
    print("RESULT: TLS Finished / AEAD rejection probes passed against local QEMU guest")
