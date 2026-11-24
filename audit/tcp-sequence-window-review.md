# TCP sequence and ACK-window review

Date: 2026-11-24

## Scope

Static review of the pinned current upstream `src/tcp.asm`
(`cb9f76a5a100c418bfcaeddcd4f137d30ab489d2`), correlated with the existing
three-revision synthetic TAP matrix in `test_tcp_ack_mss.py` and the
assertive run [45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924).

No traffic was sent to the production service. This note does not modify the
frozen `bounty` branch.

## Sequence-number admission

At `.est`, the implementation computes, with 32-bit modular arithmetic:

```text
delta = SEG.SEQ - C_NXT
admitted when (delta + 0x10000) >> 17 == 0
```

The accepted interval is therefore inclusive:

- lower edge: `SEG.SEQ = C_NXT - 65,536` (modulo 2^32);
- upper edge: `SEG.SEQ = C_NXT + 65,535` (modulo 2^32).

This is a 131,072-value interval. The expression is deliberately wrap-aware;
it is not a conventional signed comparison. A segment outside this interval
takes the `.oseq` path rather than the normal in-order/trim/hold processing.

The current code then distinguishes an old/reordered segment from a segment
that does not belong to the connection. In the latter case, it does not take
the packet's ACK, payload, FIN, or advertised window; it emits the current ACK.
The SYN-cookie exception in `.odd` is conditional on the connection's
`F_SYN` state and a successful `ckx` check.

## ACK admission

For an in-window sequence number, the code computes:

```text
ack_delta = SEG.ACK - C_ACK
sent      = C_SND - C_ACK
```

An ACK that advances beyond the outstanding range (`ack_delta > sent`) goes
to `.oack`. An ACK within the inclusive range proceeds through `.ak0/.ak1`;
only that path advances `C_ACK`. An ACK equal to `C_ACK` is a duplicate ACK,
not progress. ACKs behind `C_ACK` are classified separately so that reordered
data can still be considered without treating the stale ACK as progress.

The `.oack` calculation shifts the distance behind the current ACK by 19
bits. This is part of the implementation's bounded reordering heuristic; it
must not be read as permission to advance `C_ACK` using an old ACK.

## Existing dynamic evidence

The existing synthetic QEMU/TAP matrix sends a valid cookie ACK first, then
sends data with ACK offsets +1, +63, +64, +65,535 and +65,536 beyond
`SND.NXT`. It repeats the boundary matrix with `SND.NXT=0xFFFFFFC2`,
where +65,536 wraps to `0x0000FFC2`.

Observed differential:

- frozen bounty: HTTP response for all tested out-of-window ACK offsets,
  including the forced-wrap case;
- first upstream fix and pinned current upstream: no HTTP payload for those
  same cases.

Evidence: [three-way matrix](https://github.com/miSultanato/k15/actions/runs/45468109924)
and [forced-wrap matrix](https://github.com/miSultanato/k15/actions/runs/45413051340).

This is a reproducible ACK-window validation defect in the frozen target.
The test demonstrates application data being processed despite an ACK beyond
the server's advertised next sequence number. It does not, by itself, prove
remote code execution, memory disclosure, key recovery, or a way to inject
data without also satisfying the sequence-number and tuple constraints.

## FIN/RST and exact-edge status

The static paths show that RST handling is separate and checks the packet
sequence against `ackno` before freeing a slot. FIN is consumed only after
the segment passes the sequence/ACK classification and reaches the normal
data path. The current test matrix does not independently assert all
combinations of out-of-window ACK with FIN/RST, nor every exact sequence
window edge.

A new local TAP test, `test_tcp_rst_sequence.py`, now creates a cookie-backed
connection, sends a one-byte request prefix, observes the server's ACK (the
wire value of `ackno`), then tries RST at that exact sequence and at -1/+1.
It sends the remaining request at the next client sequence so that a freed
slot cannot be silently recreated as the original SYN-cookie connection.
The exact RST should prevent HTTP processing; either off-by-one RST should
leave the connection alive and allow the request to complete. This is a
deterministic behavioral oracle rather than merely checking for an ACK.
The new three-revision workflow execution is pending; no runtime result is
claimed yet.

No new FIN/RST vulnerability is claimed from source inspection alone. Exact
client-sequence window edges (`-65,537`, `-65,536`, `-1`, `0`,
`+65,535`, `+65,536`) with payload and FIN controls remain a separate
coverage task. Each case must prove state change or application processing,
not just the presence of an ACK response.

## Assessment

The out-of-window ACK defect is already dynamically established and fixed in
both compared upstream revisions. The arithmetic in current upstream is
internally consistent at the 32-bit wrap boundary covered by the existing
test. The exact client-sequence admission edges and FIN/RST combinations
remain untested; they are coverage gaps, not findings.
