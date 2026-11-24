# k15 bounty audit — executive status

**Updated:** 2026-11-24  
**Target:** `FileSherlock/k15` bounty source, frozen at
`ab93479ebc7c85274c722b16897148286d1cfca3`  
**Audit harness:** public fork `miSultanato/k15`, branch `main`

## Bottom line

No private-key disclosure or practical key-recovery exploit has been found.

Several concrete defects are now reproduced against the frozen image. A new short-site QEMU differential confirms a **W^X boundary failure**: with a one-file synthetic site ending in a `RET` byte, the frozen image executes that site byte and continues serving, while both tested upstream revisions fault before serving. The most notable memory-safety-adjacent result remains a **same-link stale-buffer disclosure through a 24-byte ARP request**: the frozen image returned a synthetic marker left in a previous receive buffer. Neither tested upstream image returned that marker. Neither result demonstrates private-key disclosure or Internet reachability.

The audit also reproduces authenticated TLSInnerPlaintext validation failure, TLS record-validation, TCP ACK-window and MSS defects. Some remain present in upstream framing-fix commit `a2d8893`; others are fixed there. The bounty target branch remains unchanged and pinned to its original commit. Current upstream main is pinned separately at `cb9f76a5a100c418bfcaeddcd4f137d30ab489d2`.

## Confirmed differential evidence

| Finding | Frozen bounty | First fix `a2d8893` | Current upstream main `cb9f76a` | Evidence |
| --- | --- | --- | --- | --- |
| ClientHello framing | Accepts five malformed cases | Rejects all five with fatal `decode_error` | Same rejection | [initial](https://github.com/miSultanato/k15/actions/runs/45381737629), [current comparison](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| ClientHello fields | Accepts 33-byte session ID, non-null compression, wrong handshake type and legacy_version 0x0301 | Rejects or normalizes all four | Same as first fix | [field tests](https://github.com/miSultanato/k15/actions/runs/45399706214), [handshake type](https://github.com/miSultanato/k15/actions/runs/45400449845), [current comparison](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Client Finished | Corrupted Finished followed by valid application data still gets HTTP | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| AEAD tag failure | Bad tag ignored; original valid same-sequence record processed | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Dummy ChangeCipherSpec | Missing after normal ServerHello with 32-byte session ID | Sent after ServerHello | Sent after ServerHello | [first fix](https://github.com/miSultanato/k15/actions/runs/45395033747), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Short ARP stale buffer | 24-byte ARP request returns synthetic marker from previous RX buffer | No marker reply observed | No marker reply observed | [first fix](https://github.com/miSultanato/k15/actions/runs/45397011333), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| IPv4 checksum / malformed ARP fields | Invalid IPv4-checksum SYN and malformed ARP fields still receive replies | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45396434723), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| TCP ACK-window | ACK offsets +1, +63, +64, +65535 and +65536 beyond `SND.NXT` all still get HTTP responses | No HTTP payload for all offsets | Same as first fix | [expanded TAP matrix](https://github.com/miSultanato/k15/actions/runs/45412713955) |
| Peer MSS=100 | Completes handshake and sends 180-byte segment; SYN-ACK advertises MSS=1460 | No SYN-ACK | No SYN-ACK | [first fix](https://github.com/miSultanato/k15/actions/runs/45397630737), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |\n| SYN cookie time component | Delayed first ACK after 65s is accepted and following HTTP request processed | Same | Same | [three-way TAP test](https://github.com/miSultanato/k15/actions/runs/45410737525) |
| HTTPS methods | Lowercase `get` gets no HTTP response on bounty; `FOO` returns 405 | Lowercase `get` and `FOO` return 405 | Same as first fix | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| Missing Host header | GET without Host returns 200 | GET without Host returns 200 | GET without Host returns 400 | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| TLSInnerPlaintext without content type | Authenticated 1-byte and 300-byte all-zero inner plaintext records are accepted; a following valid request is processed | Closes connection before following request | Same as first fix | [three-way corrected test](https://github.com/miSultanato/k15/actions/runs/45409977046) |
| ECDSA nonce boundaries | `n+1` aliases `1`; `n-1` verifies; `n` does not | Not compared | Not compared | [frozen signer test](https://github.com/miSultanato/k15/actions/runs/45393554079) |

## Additional negative evidence

- The local upstream hostile-client regression suite passes, including malformed
  ClientHello cases. [#45382026675](https://github.com/miSultanato/k15/actions/runs/45382026675)
- Lowercase `get` and unknown `FOO` HTTP methods both returned HTTP 200 on all three
  tested images; the reported method hang was not reproduced.
  [first fix](https://github.com/miSultanato/k15/actions/runs/45400915976),
  [current main](https://github.com/miSultanato/k15/actions/runs/45401501930)
- Controlled SMP slot races RACE=1/2/3 pass on the frozen image.
  [#45382612903](https://github.com/miSultanato/k15/actions/runs/45382612903)
- 10,240 + 1,024 local QEMU nonces showed no duplicates or cross-boot overlap;
  10M native runner RDRAND samples showed no adjacent or lag-four repeats.
  These are finite samples, not proof of production CPU behavior.
  [#45387618913](https://github.com/miSultanato/k15/actions/runs/45387618913)
- One 256 MiB guest-RAM snapshot after 1,024 handshakes contained no plaintext
  synthetic-scalar patterns and six expected Montgomery-form patterns. This
  does not inspect CPU registers or transient states.
  [#45384777117](https://github.com/miSultanato/k15/actions/runs/45384777117)
- 60,000 ClientHello cases and 3,191 malformed raw frames passed on both
  revisions. [#45396434783](https://github.com/miSultanato/k15/actions/runs/45396434783)

## Interpretation and limits

- The ARP result is a real, local receive-buffer disclosure using synthetic
  marker bytes. It is not evidence of private-key disclosure, memory corruption,
  or an Internet-reachable exploit.
- The Finished and AEAD tests show that the guest continues processing valid
  application data after those malformed records. They do not show that an
  attacker without the traffic secret can forge authenticated application data.
- Invalid IPv4 checksums and malformed full-length ARP fields are accepted, but
  no useful consequence beyond protocol-validation weakness has been shown.
- The ECDSA boundary test confirms the frozen P-256 assembly signer treats
  `n+1` like `1`; it does not demonstrate that real RDRAND produces a
  practically exploitable nonce distribution.
- The one guest-RAM snapshot and finite nonce samples cannot prove absence of
  all transient plaintext or all hardware RNG failures.

## Next work

1. Finish the post-HelloRetryRequest ServerHello/CCS differential; the current
   probe elicits HRR but does not yet send the second ClientHello.
2. Expand ACK-window tests around below/equal/inside/above limits and 32-bit
   wraparound; expand MSS tests across 0..215.
3. Keep investigating whether the short-ARP stale-buffer disclosure can expose
   anything beyond synthetic network-buffer data. Do not attempt to access
   production memory.
4. Reconcile remaining independent findings #1, #4, #6, #11–12 and #17–20 with
   exact deterministic tests where they materially affect security.

Do not merge upstream development fixes into the frozen bounty branch. All
dynamic tests remain local, offline and synthetic-key only; no request is sent
to `15kb.org`.
