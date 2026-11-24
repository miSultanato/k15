#!/usr/bin/env python3
"""Patch the Go TLS client serializer so its malformed ClientHello is also transcripted.

The one-byte-short 24-bit handshake length is applied before crypto/tls writes
or hashes the ClientHello. This avoids the invalid experiment of mutating wire
bytes after the TLS library has already hashed a valid ClientHello.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

MARKER = "K15_TRANSCRIPT_MALFORMED_CLIENT_HELLO"
OLD = """func (m *clientHelloMsg) marshal() ([]byte, error) {
	return m.marshalMsg(false)
}"""
NEW = """func (m *clientHelloMsg) marshal() ([]byte, error) {
	raw, err := m.marshalMsg(false)
	if err != nil {
		return nil, err
	}
	// K15_TRANSCRIPT_MALFORMED_CLIENT_HELLO: mutate the bytes returned to
	// both writeHandshakeRecord and transcriptMsg, not a later wire copy.
	if len(raw) >= 4 && raw[0] == typeClientHello {
		n := uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		if n > 0 {
			n--
			raw[1], raw[2], raw[3] = byte(n>>16), byte(n>>8), byte(n)
		}
	}
	return raw, nil
}"""

def main() -> None:
    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    source = goroot / "src" / "crypto" / "tls" / "handshake_messages.go"
    text = source.read_text(encoding="utf-8")
    if MARKER in text:
        print(f"PASS: Go crypto/tls already patched at {source}")
        return
    if OLD not in text:
        raise SystemExit(
            "FAIL: unsupported Go crypto/tls source layout; "
            "clientHelloMsg.marshal() did not match the reviewed patch anchor"
        )
    source.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    check = source.read_text(encoding="utf-8")
    if MARKER not in check:
        raise SystemExit("FAIL: Go crypto/tls patch did not persist")
    print(f"PASS: patched {source}; ClientHello length mutation occurs before transcript hashing")

if __name__ == "__main__":
    main()
