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

## Test status and next steps

No dynamic test is claimed by this note. The following are source-derived
test plans, not reproduced findings:

1. Corrupted IPv4 checksum with correct TCP checksum.
2. ARP field-by-field malformed request matrix.
3. ACK range and wraparound state matrix.
4. SYN MSS threshold matrix and actual outbound segment sizes.
5. ECDSA deterministic boundary vectors at `n-1`, `n`, and `n+1`; retain
   the existing `2^256-1` and `2^256-2` reference self-test coverage.

All tests remain offline against the frozen image in ephemeral QEMU. No
production probes, load tests, or memory access are permitted.
