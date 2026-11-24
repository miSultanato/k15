#!/usr/bin/env python3
"""Local-only TLS 1.3 malformed TLSInnerPlaintext probes.

A normal request first advances the client's application-data sequence number.
The test then sends authenticated records whose decrypted content is all zero
bytes (there is no non-zero inner content type), followed by a valid request.
Only a synthetic local QEMU guest is contacted.
"""
from __future__ import annotations

import socket
import ssl
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

if len(sys.argv) != 2:
    raise SystemExit("usage: test_tls_inner_plaintext.py TARGET")

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target / "tools"))
from tlsclient import BioClient, context  # noqa: E402

HOST = "127.0.0.1"
PORT = 8443
EXPECT = (target / "www" / "index.html").read_bytes()
REQUEST = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


class Client(BioClient):
    def __init__(self, ctx):
        super().__init__(socket.create_connection((HOST, PORT), timeout=5), ctx)

    def fetch(self):
        self.pump(lambda: self.tls.write(REQUEST))
        response = b""
        while not response.endswith(EXPECT):
            response += self.pump(lambda: self.tls.read(4096))
        return response


def expand(secret: bytes, label: bytes, length: int) -> bytes:
    info = length.to_bytes(2, "big") + bytes([6 + len(label)]) + b"tls13 " + label + b"\0"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def seal(secret: bytes, sequence: int, inner: bytes) -> bytes:
    key = expand(secret, b"key", 16)
    iv = expand(secret, b"iv", 12)
    nonce = (int.from_bytes(iv, "big") ^ sequence).to_bytes(12, "big")
    header = bytes((23, 3, 3)) + (len(inner) + 16).to_bytes(2, "big")
    return header + AESGCM(key).encrypt(nonce, inner, header)


def keyed_client():
    keylog = tempfile.NamedTemporaryFile()
    ctx = context()
    ctx.keylog_filename = keylog.name
    client = Client(ctx)
    client.sock.settimeout(3)
    client.handshake()
    client.fetch()  # consumes client application-data sequence number zero
    secret = None
    for line in Path(keylog.name).read_text(encoding="ascii").splitlines():
        fields = line.split()
        if fields and fields[0] == "CLIENT_TRAFFIC_SECRET_0":
            secret = bytes.fromhex(fields[2])
            break
    if secret is None:
        raise RuntimeError("OpenSSL did not write CLIENT_TRAFFIC_SECRET_0")
    return client, secret, keylog


def observe(label: str, inner: bytes) -> None:
    client, secret, keylog = keyed_client()
    wire = seal(secret, 1, inner) + seal(secret, 2, REQUEST + b"\x17" + bytes(40))
    received = bytearray()
    try:
        client.sock.sendall(wire)
        while True:
            received.extend(client.pump(lambda: client.tls.read(4096)))
    except ConnectionError:
        received.extend(b"[closed]")
    except (OSError, ssl.SSLError):
        received.extend(b"[nothing more]")
    finally:
        client.close()
        keylog.close()

    if b"HTTP/1." in received:
        outcome = "processed following valid application request"
    elif b"[closed]" in received:
        outcome = "closed connection without processing following request"
    else:
        outcome = "no HTTP response; closure not conclusively observed"
    print(f"{label}: {outcome}; response_bytes={len(received)}")


if __name__ == "__main__":
    observe("TLSInnerPlaintext=1 zero byte", bytes(1))
    observe("TLSInnerPlaintext=300 zero bytes", bytes(300))
