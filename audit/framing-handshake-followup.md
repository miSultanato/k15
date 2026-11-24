# ClientHello framing: full-handshake follow-up

Date: 2026-11-24

## Purpose

Close the remaining gap between the reproducible framing probes and the
community/owner statement that a malformed ClientHello can complete a TLS
handshake. This is an offline protocol test against locally built images only.
It must not contact `15kb.org` or use production credentials.

## Current evidence

The current `audit/test_clienthello_framing.py` sends five malformed cases
to the frozen image and checks only that the first response is a ServerHello:

- inner handshake length set to zero;
- inner handshake length one byte short;
- inner handshake length one byte long;
- inner handshake length set to the maximum 24-bit value;
- outer TLS record length one byte short while the full body is sent.

The differential workflow checks that the frozen image accepts those cases
and upstream commit `a2d8893261b2be15b44c86d6f4483d65820e943a` responds with
fatal `decode_error`. This is a confirmed parser/framing discrepancy, but
the present probe does not prove that a client validates the server Finished
or exchanges application data.

The project owner's public comment says the short inner ClientHello length
still completes the handshake and that the issue was fixed on `dev`:
https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/

The independent source audit also lists that the frozen server does not
verify the client's Finished (finding 9):
https://github.com/FileSherlock/k15/issues/1

These reports are useful context, not substitutes for our own end-to-end
reproduction.

## Protocol detail that the next test must respect

TLS 1.3 Finished authenticates the transcript hash. It is not enough to
observe a ServerHello or even the encrypted server flight. A client that
changes bytes in transit while retaining the original ClientHello transcript
will generally calculate a different transcript from the server and reject
the server Finished.

Therefore the test client must construct the malformed ClientHello as its
actual handshake message, and use exactly the bytes the server receives in
its transcript calculation:

- For an inner-length mismatch, hash the entire malformed handshake message,
  including its intentionally incorrect 24-bit length, because the frozen
  server bounds the message by the enclosing record payload.
- For an outer-record mismatch, hash only the handshake bytes actually
  included by the shorter record length. Bytes outside that record must not
  be included in the client transcript if they are not processed by the
  server.

The current OpenSSL `MemoryBIO` helper is not sufficient if it generates a
normal ClientHello and the test mutates the emitted bytes afterward: OpenSSL's
internal transcript would still contain the original bytes. The new purpose-built
client avoids that mismatch by constructing the malformed handshake bytes before
computing the transcript hash.

## Implementation status (2026-11-24)

A purpose-built client is now implemented in `test_malformed_clienthello_handshake.py`.
It constructs the short-length ClientHello before transcript hashing, derives the
TLS 1.3 key schedule, verifies the server CertificateVerify and Finished, then
sends a correctly encrypted client Finished and HTTP request. The differential
runner invokes it against the frozen bounty and both pinned upstream images.
The code and workflow trigger are committed; the next Actions run must validate
the crypto/transcript implementation before this finding is considered closed.

The implementation now covers both framing variants independently:

1. **Inner-short:** the handshake header declares one byte less than the full
   body; the outer TLS record carries the complete malformed handshake, and
   the client hashes that complete malformed message.
2. **Outer-short:** the handshake header declares the full body, but the TLS
   record length is one byte short. A final byte in an unknown extension is
   still sent on TCP outside the record; the client hashes only the record
   payload prefix that the server processes.

The outer-short case deliberately uses a non-conforming client that mirrors
the server's truncated transcript. It does not claim that an ordinary,
standards-compliant TLS client will complete the handshake.

## Assertions implemented; pending differential execution

The local-only test now:

1. Build the exact frozen bounty image and the exact fixed upstream image.
2. Use a purpose-built or instrumented TLS 1.3 client that controls the
   ClientHello bytes before transcript hashing.
3. Negotiate the supported X25519 / AES-128-GCM / SHA-256 suite using a
   synthetic certificate and key generated inside the ephemeral runner.
4. Verify the server's CertificateVerify signature and, critically, verify
   the server Finished against the transcript built from the exact transmitted
   ClientHello bytes.
5. Send the client Finished and an encrypted HTTP request.
6. Verify the encrypted HTTP response and its contents.
7. Run the same malformed ClientHello against the fixed image and require a
   fatal `decode_error` before a ServerHello.
8. Keep all key logs, certificates, private keys, images and packet captures
   inside the ephemeral runner; upload no artifacts.

The same assertions run separately for both inner-short and outer-short.
The test is committed and wired into the differential runner, but it is not
closed until a new Actions run passes on the frozen bounty and both pinned
upstream images.

## Interpretation boundary

Even a successful end-to-end handshake would establish a TLS protocol
conformance defect, not private-key disclosure, memory corruption, or a
practical route to recover the bounty scalar. Keep the framing finding
separate from the key-extraction objective.


## HRR trigger experiments (2026-11-24)

A local Go TLS 1.3 client configured with P-256 first and X25519 second
completed a normal handshake on all three pinned images in [run 45417214217](https://github.com/miSultanato/k15/actions/runs/45417214217): one ClientHello, one ServerHello, no HRR. This shows that this particular offer does not force a retry; P-256 is accepted when X25519 is also present in the supported groups list. The same trace independently confirmed the normal-path dummy CCS difference: frozen bounty sent zero server CCS records; both upstream revisions sent one after ServerHello. A stock OpenSSL attempt had the same no-HRR result.

The next probe places P-384 first and X25519 second. If the server does not
support P-384, this should preserve X25519 in supported_groups while omitting
an X25519 key share from the first ClientHello, forcing HRR. The updated
Go-based probe is local-only and captures both directions' TLS records.
Its result must be inspected before claiming that a second ClientHello or
HRR was exercised.

## Safety

- Frozen target remains `ab93479ebc7c85274c722b16897148286d1cfca3`.
- Do not modify the `bounty` branch or merge upstream fixes into it.
- Do not send malformed traffic to the production server.
- Do not run load or denial-of-service tests.
