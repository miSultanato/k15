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
- [assertive three-way ACK/MSS matrix, run 45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924)
- [forced-wrap matrix, run 45413051340](https://github.com/miSultanato/k15/actions/runs/45413051340)
- Test implementation: `audit/test_tcp_ack_mss.py`, especially
  `fetch_after_handshake`, `test_bad_ack` and `test_ack_boundary_matrix`.

## What the test proves

- A synthetically established connection can carry application data despite
  an ACK outside the server's acceptable sent-data range.
- The behavior is present in the frozen bounty image and absent in the two
  tested upstream revisions.
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

If further work is justified, use only isolated QEMU/TAP guests and synthetic
tuples to test whether a single invalid-ACK data segment advances receive
state when its payload is incomplete, followed by a legitimate retransmission.
Record the server ACK and the eventual HTTP result. Do not attempt a blind
packet-injection campaign against any public host.
