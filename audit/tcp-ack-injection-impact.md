# TCP out-of-window ACK acceptance: impact and attacker model

Date: 2026-11-25

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Finding

The frozen image processes in-order client payload on an established TCP
connection even when the segment's ACK is 65,536 beyond the server's
`SND.NXT`. The defect is in the frozen `src/os.asm` connection path:
when the ACK exceeds the outstanding range, control reaches `.odd`; because
the connection is no longer in `F_SYN`, execution falls through to `.ak`
instead of rejecting the segment's payload. The normal sequence-number path
then advances `C_NXT` and processes the payload.

The bounded QEMU/TAP test performs a normal synthetic handshake, sends the
correct client sequence number, then sends a valid HTTP request with a
deliberately invalid ACK. It observes an HTTP response on the frozen image
for offsets +1, +63, +64, +65,535 and +65,536 beyond `SND.NXT`, including
a case where the arithmetic wraps at 2^32. Both tested upstream revisions
reject these packets without returning HTTP payload.

Evidence:
- [latest three-way protocol, ACK/MSS, partial-payload and forced-wrap run 45559938127](https://github.com/miSultanato/k15/actions/runs/45559938127)
- [sequence-aware full-request differential, run 45553389873](https://github.com/miSultanato/k15/actions/runs/45553389873)
- [earlier assertive matrix, run 45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924)
- The sequence-aware request-consumption test sends a 69-byte missing-path
  request with an invalid ACK, then a 48-byte normal request at the same TCP
  sequence. Frozen response ACK `0x6789ac13` identifies the 69-byte request;
  both upstream response ACKs `0x6789abfe` identify the 48-byte request.
  This confirms that the invalid-ACK payload is consumed first only by the
  frozen image.
- A second probe sends only a 42-byte incomplete HTTP prefix with an invalid
  ACK, then retransmits a complete 48-byte request at the original sequence.
  The frozen image immediately ACKs `0x789abd09` (42 bytes consumed), while
  both upstream images ACK `0x789abcdf` (no receive-state advance). After the
  retransmission, all three ACK `0x789abd0f` and return an HTTP response. In
  the frozen image the first 42 retransmitted bytes are therefore treated as
  old and discarded; only the final six bytes are appended to the injected
  prefix. This is a reproducible TCP stream-desynchronization effect, not
  proof of an off-path attacker.
- Both probes also pass in the forced 32-bit sequence-wrap build.
- Test implementation: `audit/test_tcp_ack_mss.py`, especially
  `fetch_after_handshake`, `test_bad_ack`, `test_ack_boundary_matrix` and
  `test_invalid_ack_request_injection`.

## What the test proves

- A synthetically established connection can carry application data despite
  an ACK outside the server's acceptable sent-data range.
- With two different HTTP payloads at the same client sequence, the response
  ACK identifies which payload length advanced receive state: the frozen
  image consumes the invalid-ACK payload; both tested upstream revisions
  reject it and consume the following valid-ACK payload instead.
- A partial invalid-ACK payload advances the frozen receive sequence through
  its 42-byte prefix before the complete legitimate retransmission arrives;
  the two upstream revisions do not acknowledge that prefix and accept the
  full request from the original sequence.
- An incomplete invalid-ACK prefix advances the frozen receive sequence by
  42 bytes before any complete HTTP request exists. The two upstream revisions
  leave the sequence unchanged. A later same-sequence retransmission is
  trimmed differently by the frozen image, confirming stream desynchronization.
- Both effects are reproduced in the ordinary sequence range and in a forced
  32-bit sequence-wrap build.
- The request is accepted because its TCP sequence number is valid; the test
  does not bypass the four-tuple or sequence-number checks.

## Attacker model and impact boundary

The test is not an off-path injection demonstration. It knows the synthetic
client's source port, sequence number and the server's SYN-cookie response,
and it injects frames directly into an isolated TAP network.

An off-path attacker would still need to target the victim's four-tuple and
guess a sequence number within the receive window. The independent audit's
rough estimate of about 2^16 sequence guesses is a threat-model estimate,
not a measured Internet attack. No blind-injection race, packet-loss
conditions, NAT behavior, or practical success rate has been demonstrated.

If an attacker can inject a segment with a valid in-window sequence number,
the missing ACK validation removes an additional TCP consistency check. On
plain HTTP (port 80), the payload can be interpreted as request bytes and
the server's response is sent to the victim tuple. On HTTPS, injected
application bytes still need to pass TLS record authentication; the ACK
defect alone does not forge an AEAD tag or reveal traffic keys. A failed TLS
record may nevertheless leave TCP sequence state advanced, potentially
desynchronizing the legitimate client; that consequence should remain a
separate, explicitly tested claim.

This is a TCP state-validation weakness, not evidence of memory corruption,
remote code execution, TLS key recovery, or a practical off-path exploit.

## Assessment

Keep this as a reproducible, bounty-specific TCP validation defect with
conditional blind-injection relevance. The dynamic test proves the
acceptance rule, not the feasibility of an off-path attack. The upstream
fixes in the tested revisions reject the same invalid-ACK matrix.

## Next bounded validation

The remaining high-value question is the HTTPS consequence. An initial
purpose-built probe, `test_tls_tcp_ack_desync.py`, now drives TLS 1.3 over a
synthetic raw-TCP/TAP connection, sends a corrupted 16-byte record prefix with
an invalid ACK, and retransmits the authenticated record at the original TCP
sequence. Its three-way differential is pending; until it passes, no TLS
stream-desynchronization consequence is claimed. Keep this strictly in
isolated QEMU/TAP guests with synthetic keys and tuples. It must not be
described as TLS record forgery or an off-path exploit.
