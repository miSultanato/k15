#!/usr/bin/env python3
"""Complete a TLS 1.3 handshake with an intentionally short ClientHello length.

The malformed ClientHello is the actual handshake message sent on the wire and
is also the exact byte sequence hashed into the client transcript. This test
uses synthetic X25519 material and verifies the server CertificateVerify and
Finished before sending an encrypted HTTP request.

Usage: test_malformed_clienthello_handshake.py TARGET accept|reject
Only connects to 127.0.0.1:8443.
"""
from __future__ import annotations

import hashlib
import hmac
import select
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509


HOST = "127.0.0.1"
PORT = 8443
ZERO32 = bytes(32)
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)
REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Connection: close\r\n\r\n"
)


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes((len(full_label),))
        + full_label
        + bytes((len(context),))
        + context
    )
    return hkdf_expand(secret, info, length)


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, 32)


def xor_nonce(iv: bytes, sequence: int) -> bytes:
    return bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))


def traffic_key_iv(secret: bytes) -> tuple[bytes, bytes]:
    return (
        hkdf_expand_label(secret, b"key", b"", 16),
        hkdf_expand_label(secret, b"iv", b"", 12),
    )


def decrypt_record(record: bytes, secret: bytes, sequence: int) -> bytes:
    header = record[:5]
    key, iv = traffic_key_iv(secret)
    return AESGCM(key).decrypt(
        xor_nonce(iv, sequence), record[5:], header
    )


def encrypt_record(secret: bytes, sequence: int, content: bytes, inner_type: int) -> bytes:
    key, iv = traffic_key_iv(secret)
    inner = content + bytes((inner_type,))
    header = bytes((23, 3, 3)) + (len(inner) + 16).to_bytes(2, "big")
    ciphertext = AESGCM(key).encrypt(
        xor_nonce(iv, sequence), inner, header
    )
    return header + ciphertext


def strip_inner_plaintext(plaintext: bytes) -> tuple[bytes, int]:
    end = len(plaintext) - 1
    while end >= 0 and plaintext[end] == 0:
        end -= 1
    if end < 0:
        fail("TLSInnerPlaintext contains no content type")
    return plaintext[:end], plaintext[end]


def parse_handshakes(stream: bytes) -> list[tuple[int, bytes, bytes]]:
    messages = []
    offset = 0
    while offset < len(stream):
        if len(stream) - offset < 4:
            fail("truncated handshake header")
        length = int.from_bytes(stream[offset + 1 : offset + 4], "big")
        end = offset + 4 + length
        if end > len(stream):
            fail("truncated handshake message")
        raw = stream[offset:end]
        messages.append((stream[offset], stream[offset + 4 : end], raw))
        offset = end
    return messages


def read_records(sock: socket.socket, stop, timeout: float = 6.0) -> list[bytes]:
    pending = bytearray()
    records: list[bytes] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while len(pending) >= 5:
            size = int.from_bytes(pending[3:5], "big")
            end = 5 + size
            if len(pending) < end:
                break
            records.append(bytes(pending[:end]))
            del pending[:end]
            if stop(records):
                return records
        wait = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([sock], [], [], wait)
        if not ready:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        pending.extend(chunk)
    return records


def make_client_hello() -> tuple[bytes, x25519.X25519PrivateKey]:
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    session_id = bytes.fromhex("102132435465768798a9bacbdcedfe0f") * 2

    def extension(kind: int, value: bytes) -> bytes:
        return struct.pack("!HH", kind, len(value)) + value

    extensions = b"".join(
        (
            extension(43, b"\x02\x03\x04"),                 # TLS 1.3
            extension(10, b"\x00\x02\x00\x1d"),           # X25519
            extension(13, b"\x00\x02\x04\x03"),           # ecdsa_secp256r1_sha256
            extension(51, b"\x00\x24\x00\x1d\x00\x20" + public),
        )
    )
    body = (
        b"\x03\x03"
        + bytes.fromhex("00112233445566778899aabbccddeeff") * 2
        + bytes((len(session_id),))
        + session_id
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    # Deliberately declare one byte less than the complete body. The outer TLS
    # record still carries every byte, and this exact malformed handshake is
    # what the client hashes below.
    handshake = b"\x01" + (len(body) - 1).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record, private


def parse_server_hello(raw: bytes, session_id: bytes) -> bytes:
    if raw[0] != 2:
        fail(f"expected ServerHello, got handshake type {raw[0]}")
    body = raw[4:]
    if body[:2] != b"\x03\x03":
        fail("ServerHello legacy_version is not 0x0303")
    if body[2:34] == HRR_RANDOM:
        fail("server sent HelloRetryRequest; test requires a direct X25519 ServerHello")
    sid_len = body[34]
    if body[35 : 35 + sid_len] != session_id:
        fail("ServerHello did not echo the ClientHello session ID")
    at = 35 + sid_len
    if body[at : at + 2] != b"\x13\x01":
        fail("server did not select TLS_AES_128_GCM_SHA256")
    at += 3  # cipher suite and legacy compression
    ext_len = int.from_bytes(body[at : at + 2], "big")
    at += 2
    end = at + ext_len
    server_share = None
    while at + 4 <= end:
        kind = int.from_bytes(body[at : at + 2], "big")
        size = int.from_bytes(body[at + 2 : at + 4], "big")
        value = body[at + 4 : at + 4 + size]
        if len(value) != size:
            fail("truncated ServerHello extension")
        if kind == 51:
            if value[:2] != b"\x00\x1d" or value[2:4] != b"\x00\x20":
                fail("server key share is not X25519")
            server_share = value[4:36]
        at += 4 + size
    if server_share is None or len(server_share) != 32:
        fail("ServerHello has no complete X25519 key share")
    return server_share


def parse_certificate_chain(body: bytes) -> list[bytes]:
    if not body:
        fail("empty Certificate message")
    context_len = body[0]
    at = 1 + context_len
    list_len = int.from_bytes(body[at : at + 3], "big")
    at += 3
    end = at + list_len
    certificates = []
    while at < end:
        cert_len = int.from_bytes(body[at : at + 3], "big")
        at += 3
        cert = body[at : at + cert_len]
        if len(cert) != cert_len:
            fail("truncated certificate entry")
        at += cert_len
        ext_len = int.from_bytes(body[at : at + 2], "big")
        at += 2 + ext_len
        certificates.append(cert)
    if not certificates:
        fail("Certificate message contains no certificates")
    return certificates


def verify_certificate_verify(
    certificates: list[bytes], signature: bytes, transcript_hash: bytes
) -> None:
    signed_content = (
        b" " * 64
        + b"TLS 1.3, server CertificateVerify"
        + b"\x00"
        + transcript_hash
    )
    verified = False
    for der in certificates:
        cert = x509.load_der_x509_certificate(der)
        public_key = cert.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            continue
        try:
            public_key.verify(
                signature, signed_content, ec.ECDSA(hashes.SHA256())
            )
            verified = True
            break
        except InvalidSignature:
            continue
    if not verified:
        fail("no certificate public key verified the server CertificateVerify")


def read_http_response(sock: socket.socket, server_app_secret: bytes) -> bytes:
    pending = bytearray()
    response = bytearray()
    sequence = 0
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        while len(pending) >= 5:
            size = int.from_bytes(pending[3:5], "big")
            end = 5 + size
            if len(pending) < end:
                break
            record = bytes(pending[:end])
            del pending[:end]
            if record[0] == 21:
                return bytes(response)
            if record[0] != 23:
                continue
            try:
                plain = decrypt_record(record, server_app_secret, sequence)
            except InvalidTag:
                fail(f"server application record {sequence} failed AES-GCM authentication")
            sequence += 1
            content, inner_type = strip_inner_plaintext(plain)
            if inner_type == 23:
                response.extend(content)
                if b"\r\n\r\n" in response:
                    head, _, body = response.partition(b"\r\n\r\n")
                    length = None
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1].strip())
                            break
                    if length is not None and len(body) >= length:
                        return bytes(response)
        ready, _, _ = select.select(
            [sock], [], [], max(0.0, deadline - time.monotonic())
        )
        if not ready:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        pending.extend(chunk)
    return bytes(response)


def expect_rejection(records: list[bytes]) -> None:
    if not records:
        fail("fixed image closed without a TLS alert")
    alert = next((record for record in records if record[0] == 21), None)
    if alert is None or len(alert) < 7:
        fail("fixed image did not send a fatal TLS alert")
    if alert[5] != 2 or alert[6] != 50:
        fail(f"expected fatal decode_error (2,50), got ({alert[5]},{alert[6]})")
    print("PASS: fixed image rejected the short inner handshake length with fatal decode_error")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"accept", "reject"}:
        fail("usage: test_malformed_clienthello_handshake.py TARGET accept|reject")
    target = Path(sys.argv[1]).resolve()
    if not target.is_dir():
        fail(f"target directory does not exist: {target}")

    wire, private = make_client_hello()
    handshake = wire[5:]
    session_id = bytes.fromhex("102132435465768798a9bacbdcedfe0f") * 2
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(5)
    try:
        sock.sendall(wire)
        if sys.argv[2] == "reject":
            records = read_records(
                sock,
                lambda items: any(item[0] == 21 for item in items)
                or any(item[0] == 22 for item in items),
            )
            expect_rejection(records)
            return

        records = read_records(
            sock,
            lambda items: any(item[0] == 22 for item in items)
            and any(item[0] == 23 for item in items),
        )
        server_hello_record = next((r for r in records if r[0] == 22), None)
        if server_hello_record is None:
            fail("frozen image did not send a plaintext ServerHello")
        server_messages = parse_handshakes(server_hello_record[5:])
        if len(server_messages) != 1 or server_messages[0][0] != 2:
            fail("expected one ServerHello handshake message")
        server_hello = server_messages[0][2]
        server_public = parse_server_hello(server_hello, session_id)

        shared_secret = private.exchange(
            x25519.X25519PublicKey.from_public_bytes(server_public)
        )
        early_secret = hkdf_extract(ZERO32, ZERO32)
        derived_early = derive_secret(
            early_secret, b"derived", hashlib.sha256(b"").digest()
        )
        handshake_secret = hkdf_extract(derived_early, shared_secret)
        transcript_ch_sh = hashlib.sha256(handshake + server_hello).digest()
        client_hs_secret = derive_secret(
            handshake_secret, b"c hs traffic", transcript_ch_sh
        )
        server_hs_secret = derive_secret(
            handshake_secret, b"s hs traffic", transcript_ch_sh
        )

        encrypted_records = [r for r in records if r[0] == 23]
        if not encrypted_records:
            fail("server sent no encrypted handshake flight")
        handshake_messages = []
        for sequence, record in enumerate(encrypted_records):
            plaintext = decrypt_record(record, server_hs_secret, sequence)
            content, inner_type = strip_inner_plaintext(plaintext)
            if inner_type != 22:
                fail(f"server handshake record has inner content type {inner_type}")
            handshake_messages.extend(parse_handshakes(content))

        by_type = {kind: (body, raw) for kind, body, raw in handshake_messages}
        required = (8, 11, 15, 20)
        if any(kind not in by_type for kind in required):
            fail(f"server flight omitted one of EncryptedExtensions/Certificate/CV/Finished: {[m[0] for m in handshake_messages]}")

        ee_body, ee_raw = by_type[8]
        cert_body, cert_raw = by_type[11]
        cv_body, cv_raw = by_type[15]
        finished_body, finished_raw = by_type[20]
        if len(cv_body) < 4 or cv_body[:2] != b"\x04\x03":
            fail("server CertificateVerify did not use ecdsa_secp256r1_sha256")
        sig_len = int.from_bytes(cv_body[2:4], "big")
        signature = cv_body[4 : 4 + sig_len]
        if len(signature) != sig_len:
            fail("truncated CertificateVerify signature")
        certificates = parse_certificate_chain(cert_body)
        transcript_before_cv = hashlib.sha256(
            handshake + server_hello + ee_raw + cert_raw
        ).digest()
        verify_certificate_verify(certificates, signature, transcript_before_cv)

        transcript_before_finished = hashlib.sha256(
            handshake + server_hello + ee_raw + cert_raw + cv_raw
        ).digest()
        finished_key = hkdf_expand_label(
            server_hs_secret, b"finished", b"", 32
        )
        expected_finished = hmac.new(
            finished_key, transcript_before_finished, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(finished_body, expected_finished):
            fail("server Finished did not verify against the exact malformed ClientHello transcript")

        transcript_after_finished = hashlib.sha256(
            handshake + server_hello + ee_raw + cert_raw + cv_raw + finished_raw
        ).digest()
        derived_master = derive_secret(
            handshake_secret, b"derived", hashlib.sha256(b"").digest()
        )
        master_secret = hkdf_extract(derived_master, ZERO32)
        client_app_secret = derive_secret(
            master_secret, b"c ap traffic", transcript_after_finished
        )
        server_app_secret = derive_secret(
            master_secret, b"s ap traffic", transcript_after_finished
        )

        client_finished_key = hkdf_expand_label(
            client_hs_secret, b"finished", b"", 32
        )
        client_finished_verify = hmac.new(
            client_finished_key, transcript_after_finished, hashlib.sha256
        ).digest()
        client_finished = b"\x14\x00\x00\x20" + client_finished_verify
        sock.sendall(
            encrypt_record(client_hs_secret, 0, client_finished, 22)
            + encrypt_record(client_app_secret, 0, REQUEST, 23)
        )

        response = read_http_response(sock, server_app_secret)
        if not response.startswith(b"HTTP/1.1 200"):
            fail(f"no HTTP 200 after the verified malformed handshake: {response[:120]!r}")
        print("PASS: frozen image accepted the short inner length")
        print("PASS: server CertificateVerify verified against the exact malformed ClientHello transcript")
        print("PASS: server Finished verified against the exact malformed ClientHello transcript")
        print(f"PASS: encrypted HTTP request returned {response.splitlines()[0].decode('ascii', 'replace')}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
