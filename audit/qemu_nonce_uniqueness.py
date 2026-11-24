#!/usr/bin/env python3
"""Recover synthetic ECDSA nonces from locally captured TLS 1.3 handshakes.

The server is the synthetic-key QEMU image built in this runner. The script
uses its generated test certificate key only to verify CertificateVerify and
recover the corresponding nonce; it never reads or contacts the production
key or host. Only aggregate uniqueness counts are printed.
"""
from __future__ import annotations

import hashlib
import os
import socket
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography import x509

TARGET = Path(sys.argv[1] if len(sys.argv) > 1 else "target").resolve()
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 512
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 4
sys.path.insert(0, str(TARGET / "tools"))
from tlsclient import BioClient, context  # noqa: E402

HOST, PORT = "127.0.0.1", 8443
P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class CaptureSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sent = bytearray()
        self.received = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)
        self.sock.sendall(data)

    def recv(self, size: int) -> bytes:
        data = self.sock.recv(size)
        self.received.extend(data)
        return data

    def close(self) -> None:
        self.sock.close()

    def __getattr__(self, name):
        return getattr(self.sock, name)


def records(wire: bytes):
    at = 0
    while at + 5 <= len(wire):
        length = int.from_bytes(wire[at + 3:at + 5], "big")
        end = at + 5 + length
        if end > len(wire):
            raise ValueError("truncated TLS record capture")
        yield wire[at:at + 5], wire[at + 5:end]
        at = end
    if at != len(wire):
        raise ValueError("trailing partial TLS record")


def handshake_messages(data: bytes):
    at = 0
    while at + 4 <= len(data):
        size = int.from_bytes(data[at + 1:at + 4], "big")
        end = at + 4 + size
        if end > len(data):
            raise ValueError("truncated handshake message")
        yield data[at:end]
        at = end
    if at != len(data):
        raise ValueError("trailing partial handshake bytes")


def expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def extract_cv(wire_client: bytes, wire_server: bytes, keylog_path: str, private_key):
    client_records = list(records(wire_client))
    client_hello = next(payload for header, payload in client_records
                        if header[0] == 22 and payload[:1] == b"\x01")
    if len(client_hello) < 38:
        raise ValueError("ClientHello capture is incomplete")
    client_random = client_hello[6:38].hex()

    secrets = {}
    for line in Path(keylog_path).read_text(encoding="ascii").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == client_random:
            secrets[parts[0]] = bytes.fromhex(parts[2])
    traffic_secret = secrets.get("SERVER_HANDSHAKE_TRAFFIC_SECRET")
    if traffic_secret is None:
        raise ValueError("OpenSSL key log has no server handshake traffic secret")

    server_records = list(records(wire_server))
    server_hello = None
    encrypted = None
    for header, payload in server_records:
        if header[0] == 22 and payload[:1] == b"\x02":
            server_hello = payload
        elif header[0] == 23:
            encrypted = (header, payload)
    if server_hello is None or encrypted is None:
        raise ValueError("ServerHello or encrypted handshake flight missing")

    header, ciphertext = encrypted
    key = expand_label(traffic_secret, b"key", 16)
    iv = expand_label(traffic_secret, b"iv", 12)
    plaintext = AESGCM(key).decrypt(iv, ciphertext, header)
    last = len(plaintext.rstrip(b"\x00")) - 1
    if last < 0 or plaintext[last] != 22:
        raise ValueError("decrypted record is not a handshake record")
    messages = list(handshake_messages(plaintext[:last]))
    prior = []
    cv = None
    for message in messages:
        if message[0] == 15:
            cv = message
            break
        prior.append(message)
    if cv is None:
        raise ValueError("CertificateVerify missing from server flight")

    body = cv[4:]
    scheme = int.from_bytes(body[:2], "big")
    sig_len = int.from_bytes(body[2:4], "big")
    signature = body[4:4 + sig_len]
    if scheme != 0x0403 or len(signature) != sig_len:
        raise ValueError("unexpected CertificateVerify signature scheme or length")

    transcript = client_hello + server_hello + b"".join(prior)
    transcript_hash = hashlib.sha256(transcript).digest()
    signed_content = (b" " * 64 + b"TLS 1.3, server CertificateVerify"
                      + b"\x00" + transcript_hash)
    public_key = private_key.public_key()
    public_key.verify(signature, signed_content, ec.ECDSA(hashes.SHA256()))

    r, s = decode_dss_signature(signature)
    z = int.from_bytes(hashlib.sha256(signed_content).digest(), "big")
    d = private_key.private_numbers().private_value
    k = ((z + r * d) * pow(s, -1, P256_N)) % P256_N
    if not k:
        raise ValueError("recovered zero ECDSA nonce")
    return r, min(k, P256_N - k)


def one_handshake(index: int, private_key):
    fd, keylog_path = tempfile.mkstemp(prefix="k15-keylog-")
    os.close(fd)
    try:
        ctx = context()
        ctx.keylog_filename = keylog_path
        sock = socket.create_connection((HOST, PORT), timeout=5)
        sock.settimeout(5)
        captured = CaptureSocket(sock)
        client = BioClient(captured, ctx)
        client.handshake()
        client.close()
        return extract_cv(bytes(captured.sent), bytes(captured.received), keylog_path, private_key)
    finally:
        try:
            os.unlink(keylog_path)
        except FileNotFoundError:
            pass


def main() -> None:
    key_path = TARGET / "cert" / "server.key"
    cert_path = TARGET / "cert" / "server.pem"
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != "secp256r1":
        raise SystemExit("FAIL: generated local server key is not P-256")
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
        raise SystemExit("FAIL: generated leaf certificate and local test key do not match")

    results = []
    errors = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(one_handshake, i, private_key) for i in range(COUNT)]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # report only type, never secrets or packet bytes
                errors.append(type(exc).__name__)

    rs = [r for r, _ in results]
    ks = [k for _, k in results]
    print(f"Completed TLS handshakes: {len(results)}/{COUNT}")
    print(f"Unique CertificateVerify r values: {len(set(rs))}/{len(rs)}")
    print(f"Unique recovered ECDSA nonces (± equivalence): {len(set(ks))}/{len(ks)}")
    if errors:
        print(f"Handshake/parser errors by type: {len(errors)} ({','.join(sorted(set(errors)))})")
    if len(results) != COUNT or len(set(rs)) != len(rs) or len(set(ks)) != len(ks):
        raise SystemExit("FAIL: incomplete handshakes or a repeated ECDSA nonce detected")
    print("PASS: every locally generated CertificateVerify verifies and uses a unique nonce")


if __name__ == "__main__":
    main()
