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

The transcript-faithful differential is now validated in
[run 45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415).

A purpose-built Python client in `test_malformed_clienthello_handshake.py`
constructs both malformed variants before transcript hashing, derives the
TLS 1.3 key schedule, verifies the server CertificateVerify and Finished,
sends a correctly encrypted client Finished and HTTP request, and checks the
decrypted HTTP 200 response.

Results across the three pinned images:

- **Frozen bounty:** both `inner-short` and `outer-short` complete the
  handshake and return HTTP 200.
- **First upstream fix `a2d8893`:** both variants are rejected with fatal
  `decode_error` (alert level 2, description 50).
- **Current upstream main:** same rejection for both variants.

A separate patched Go `crypto/tls` client cross-checks the `inner-short`
case. It validates the synthetic CA chain, the TLS Finished through the
standard TLS implementation, and the exact local HTTP response body.

### What the outer-short vector actually does

The outer-short ClientHello declares its full handshake-body length, but the
TLS record length is one byte shorter. The final byte outside that record is
chosen as `0x17`, the content-type byte of the next TLS record. The client
hashes only the ClientHello bytes inside the first record, then sends the
remainder of the client Finished record header/body without duplicating that
first byte. The TCP stream therefore contains two correctly aligned TLS
records, while the first record carries a truncated ClientHello.

This is a deliberately crafted raw client, not evidence that an ordinary
stock TLS client will generate or accept this sequence. The server's
CertificateVerify and Finished nevertheless verify against the exact
truncated-record transcript, and the encrypted HTTP request succeeds.

All tests use local QEMU images and synthetic credentials. No production
endpoint, key, disk image or infrastructure is touched, and the workflow
uploads no artifacts.

## Assertions validated

1. The frozen image completes the TLS 1.3 handshake for both malformed
   variants.
2. The client verifies the server CertificateVerify signature and Finished
   against the exact bytes included in the server's transcript.
3. The client sends its own correctly encrypted Finished and an encrypted
   HTTP request; the server returns HTTP 200.
4. The first upstream fix and current upstream reject both variants with
   fatal `decode_error` before ServerHello.
5. The Go cross-check independently validates the inner-short handshake,
   synthetic CA chain and exact response body.
6. Certificates, private keys, images and captures remain in the ephemeral
   runner; no artifacts are uploaded.

## Interpretation boundary

Even a successful end-to-end handshake would establish a TLS protocol
conformance defect, not private-key disclosure, memory corruption, or a
practical route to recover the bounty scalar. Keep the framing finding
separate from the key-extraction objective.


## HRR trigger experiments (2026-11-24)

A local Go TLS 1.3 client configured with P-256 first and X25519 second
completed a normal handshake on all three pinned images in
[run 45417214217](https://github.com/miSultanato/k15/actions/runs/45417214217):
one ClientHello, one ServerHello, no HRR. This offer did not force a retry;
P-256 was accepted when X25519 was also present in supported_groups.

The follow-up OpenSSL client offers P-384 first and X25519 second, preserving
X25519 in supported_groups while omitting an X25519 key share from the first
ClientHello. The differential run
[45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415)
forced and completed the HRR path on all three pinned revisions:

- each image captured exactly two ClientHellos and two ServerHellos;
- OpenSSL exited successfully with TLS 1.3 negotiated;
- frozen bounty sent zero server dummy CCS records;
- first upstream fix and current upstream each sent one server CCS record.

The relay captures both directions without modifying TLS bytes. This closes
the earlier uncertainty about whether the second ClientHello was actually
sent; the normal-path and HRR-path CCS difference is now independently
reproduced.

## Additional coverage plan

The next untested offsets and next-record prefix alignments are specified in [clienthello-truncation-record-prefix-matrix-v0.1.md](clienthello-truncation-record-prefix-matrix-v0.1.md). The matrix is NOT-RUN; the existing inner-short/outer-short and HRR results remain the only dynamic evidence cited above.

## Safety

- Frozen target remains `ab93479ebc7c85274c722b16897148286d1cfca3`.
- Do not modify the `bounty` branch or merge upstream fixes into it.
- Do not send malformed traffic to the production server.
- Do not run load or denial-of-service tests.
