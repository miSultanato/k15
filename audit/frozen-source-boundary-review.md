# Frozen-source review: TCP/IP boundaries and ECDSA nonce semantics

Date: 2026-11-24

Target: `FileSherlock/k15` commit
`ab93479ebc7c85274c722b16897148286d1cfca3`.

This is a source-reading note, not a dynamic reproduction. All observations
below are from the frozen `src/os.asm` and `tools/ec.py`. Line numbers refer
to that exact source revision and may shift in other revisions.

## 1. IPv4 header checksum is explicitly not validated

In `src/os.asm`, the IPv4 path checks EtherType, IHL exactly 5, fragment/flag
bits, protocol TCP, destination address, total length, and then computes the
TCP checksum over the pseudo-header and TCP segment (approximately lines
1358-1387).

The source comment at lines 1359-1361 explicitly acknowledges that the IPv4
header has its own checksum but says it is not used. The TCP checksum is
verified at lines 1375-1387. Therefore the narrow source-level conclusion is:
**the frozen receive path does not validate the IPv4 header checksum**.

This is not yet a demonstrated security impact. The next safe test is a
loopback/QEMU packet matrix with an otherwise valid SYN whose IPv4 checksum
is independently corrupted, while keeping the TCP checksum correct. Record
whether the guest emits SYN-ACK, drops, or resets. Also test a valid checksum
with one other header field changed, so the result is attributable to checksum
handling rather than another parser condition. Do not send this to production.

## 2. ARP request validation is narrow

The ARP path (approximately lines 1331-1357) checks the Ethernet protocol type
as ARP, operation as request, and target protocol address as OURIP. It then
constructs a reply by copying portions of the request. In this path there is
no visible validation of hardware type, protocol type, hardware-address
length, or protocol-address length before those fixed-offset reads/copies.

This is a candidate malformed-frame acceptance issue, not evidence of memory
corruption. The next test should vary one ARP field at a time (hardware type,
protocol type, hlen, plen, operation, target IP) and observe only the local
guest's reply/drop behavior. Keep frames within the allocated receive buffer
and avoid short-frame tests that could make the harness itself unsafe.

## 3. ACK handling has explicit range and sequence gates; do not overstate finding #2

After TCP checksum verification, sequence and ACK fields are converted to
host order (approximately lines 1417-1423). The ACK is compared against the
connection's `C_ACK` and `C_SND` values (1595-1605); an ACK beyond the
outstanding send range takes the `.odd` path. The receive sequence is also
compared with `C_NXT` and old/out-of-order data is handled separately
(1651-1675).

This source path suggests deliberate ACK-window validation. It does not prove
all ACK corner cases are correct, especially around SYN cookies, wraparound,
retransmission, and concurrent slot ownership. The next test should be a
deterministic connection-state matrix: ACK below `C_ACK`, equal to it,
inside the outstanding range, exactly `C_SND`, and one beyond `C_SND`;
repeat around 32-bit wrap. Assert response flags and state progression, not
merely that the guest remains alive.

## 4. MSS negotiation needs a boundary test, but source does not prove the reported defect

The SYN option parser starts with a default MSS of 536 (approximately lines
1463-1468), accepts a well-formed MSS option of length four (1481-1486), and
maps the result to one of four supported segment sizes (1508-1515). It also
parses window scaling with a cap of 14 (1487-1494).

This code is enough to justify a targeted boundary matrix, but not enough to
claim that the peer's advertised MSS is violated. Test omitted MSS and
advertised values around the mapping thresholds, especially 0, 1, 215, 216,
535, 536, 537, 1219, 1220, 1440, and values above 1440. Capture the SYN-ACK
MSS option and subsequent TCP payload sizes. A server may legally advertise
a supported MSS different from the peer's advertised MSS; compare actual
outbound segment size to the peer's receive limit, not only the option echo.

## 5. ECDSA nonce values at and above n: distinguish raw input from effective scalar

In `tools/ec.py`, `sign()` documents that it returns
`r = x(kG)` without reduction of the x-coordinate modulo n. It computes
`k2 = k - KOFF` using weak reduction, then later calls `inv(k)` before
executing the signing program (approximately lines 418-445).

The independent audit's finding #16 should therefore not be summarized as
"the signer definitely uses an invalid nonce". The important question is how
the implementation's field arithmetic and inversion interpret the raw
256-bit input. For the implementation's NIST P-256 curve, a 256-bit value can be at least n; values
`k >= n` have the same group scalar as `k mod n`, except the zero residue,
and may therefore alias a lower nonce rather than immediately produce an
invalid signature. That can affect the effective nonce distribution and
uniqueness, but requires a deterministic check.

The existing `tools/ec.py` self-test already exercises `k = 2^256-1` and
`k = 2^256-2` (its first two ECDSA iterations) and verifies the resulting
signatures with a P-256 public key. The earlier CI `make test` therefore
provides some boundary evidence; it does not explicitly isolate `n-1`, `n`,
or `n+1`, nor report their effective nonce residues.

Next add exact vectors `n-1`, `n`, and `n+1` through the reference signer
and, if possible, the assembly/VM signer with a synthetic key and digest. Verify each signature independently and record whether the
operation rejects, faults, or produces a signature. For successful signatures,
compare the recovered effective nonce modulo n. Keep this separate from
RDRAND sampling and from the synthetic periodic-nonce demonstration.


## 6. Client Finished and bad AEAD tags are silently ignored by the record path

The frozen source makes the behavior unusually explicit:

- The comment above `record` (approximately lines 2363-2370) says the
  client's Finished uses different keys and is "nothing to us".
- `record` accepts only outer content type 23 (application_data) at
  lines 2372-2377, decrypts with the client's application traffic key at
  `C_KIV+44` (2379-2384), and compares the calculated GCM tag with the
  received tag (2385-2389).
- A tag mismatch branches to `.no`; that shared exit clears carry, restores
  registers, and returns at lines 2492-2495. It does not set a fatal alert or
  mark the connection closed.
- The handshake-record dispatcher routes post-ClientHello records to
  `record` (approximately lines 1753-1775), so an encrypted Client Finished
  under handshake traffic keys is not validated by this application-key
  record handler.

This is stronger than an inference from the auditor's summary: the source
explicitly describes the client's Finished as ignored, and the bad-tag path
returns without a fatal close. It remains a source-level observation until a
local end-to-end test demonstrates what application traffic is accepted after
those records.

A safe local-only follow-up should use a purpose-built TLS 1.3 client and
synthetic keys to send, in separate connections:

1. A valid server handshake followed by a corrupted client Finished.
2. A valid client Finished followed by an application record with one
   corrupted tag byte.
3. After each invalid record, a correctly authenticated application record
   using the expected application traffic key and record sequence number.

Record whether the guest responds, silently ignores the record, closes the
connection, or serves the subsequent HTTP request. Do not treat silence as
proof of successful application-data processing. The client must calculate
the exact TLS 1.3 transcript and traffic secrets; do not mutate bytes after
the TLS library has hashed them.

These protocol behaviors may be relevant to TLS conformance or connection
state handling, but neither is by itself evidence of private-key disclosure.


## 7. Dummy ChangeCipherSpec is missing for a non-empty legacy session ID

The local differential test in [run 45395033747](https://github.com/miSultanato/k15/actions/runs/45395033747)
used an OpenSSL ClientHello with a 32-byte `legacy_session_id` and inspected
the first two server TLS records:

- Frozen bounty image: ServerHello is followed immediately by outer record
  type 23 (encrypted handshake data), not a dummy ChangeCipherSpec (type 20).
- Upstream framing-fix image `a2d8893261b2be15b44c86d6f4483d65820e943a`:
  the record immediately after ServerHello is type 20, as required.

This reproduces finding #8 and confirms that the upstream image fixes it.
The HelloRetryRequest path remains to be tested separately.


## 8. IPv4 checksum and ARP field matrix

The TAP differential test in [run 45396434723](https://github.com/miSultanato/k15/actions/runs/45396434723)
sent synthetic raw Ethernet frames to both the frozen bounty image and the
upstream framing-fix image:

- A SYN with a valid TCP checksum but deliberately corrupted IPv4 header
  checksum received a SYN-ACK on both images.
- ARP requests with hardware type 2, protocol type IPv6, hardware length 1,
  and protocol length 1 each received an ARP reply on both images.

This confirms that those fields are not rejected by either tested revision.
It does not demonstrate memory disclosure, memory corruption, or a useful
remote attack. The test uses full-length ARP frames; the separate short-frame
stale-buffer behavior described by the auditor is not yet reproduced here.

## Test status and next steps

The deterministic ECDSA boundary test now runs against the frozen assembly
signer in [GitHub Actions run 45393554079](https://github.com/miSultanato/k15/actions/runs/45393554079):
`n+1` aliases `1` and both signatures verify; `n-1` verifies; `n` (zero
modulo n) does not verify. The full bounded workflow passed. This confirms the
assembly's effective-scalar behavior for those vectors; it does not establish
practical key recovery or measure the production RDRAND distribution.

The local QEMU test in [run 45394182511](https://github.com/miSultanato/k15/actions/runs/45394182511)
reproduces both TLS behaviors end-to-end against the frozen image. A differential
run against upstream framing-fix commit `a2d8893261b2be15b44c86d6f4483d65820e943a`
([run 45394628025](https://github.com/miSultanato/k15/actions/runs/45394628025))
observed the same two behaviors on that fixed image:

- A corrupted client Finished was followed by an authenticated application
  request, and the guest returned an HTTP response.
- A corrupted application-record tag was followed by the original valid
  same-sequence record, and the guest processed it and returned HTTP.

This demonstrates that the guest does not fail the connection on either
record; it does not demonstrate a remote attacker can forge authenticated
application data or recover the server's private key. The remaining items are
source-derived test plans, not dynamically reproduced findings:

1. Exercise the dummy ChangeCipherSpec behavior on the HelloRetryRequest path.
2. Reproduce the short-ARP-frame stale-buffer behavior with synthetic marker bytes.
3. ACK range and wraparound state matrix.
4. SYN MSS threshold matrix and actual outbound segment sizes.
7. Extend nonce-distribution analysis only if a plausible attack model emerges;
   the explicit `n-1`, `n`, and `n+1` assembly boundary vectors now pass.

All tests remain offline against the frozen image in ephemeral QEMU. No
production probes, load tests, or memory access are permitted.
