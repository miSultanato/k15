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
| Short-site W^X | Executes a synthetic `RET` at the end of a one-file site and continues serving | Execution faults before service | Same as first fix | [three-way QEMU test](https://github.com/miSultanato/k15/actions/runs/45409649945) |
| ClientHello framing | Accepts five malformed cases | Rejects all five with fatal `decode_error` | Same rejection | [initial](https://github.com/miSultanato/k15/actions/runs/45381737629), [current comparison](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| ClientHello fields | Accepts 33-byte and 255-byte session IDs, non-null compression and wrong handshake type; echoes legacy_version 0x0301 | Rejects both oversized session IDs and non-null compression; rejects wrong type; responds with legacy_version 0x0303 | Same as first fix | [three-way framing/HRR run](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Client Finished | Corrupted Finished followed by valid application data still gets HTTP | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| AEAD tag failure | Bad tag ignored; original valid same-sequence record processed | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Dummy ChangeCipherSpec | Missing after normal ServerHello with 32-byte session ID | Sent after ServerHello | Sent after ServerHello | [normal path](https://github.com/miSultanato/k15/actions/runs/45417214217), [HRR path](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| HRR / second ClientHello | Completes HRR -> second ClientHello -> final ServerHello; sends 0 server CCS records | Same handshake; sends 1 server CCS record | Same as first fix | [OpenSSL wire-capture differential](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Short ARP stale buffer | 24-byte ARP request returns synthetic marker from previous RX buffer | No marker reply observed | No marker reply observed | [first fix](https://github.com/miSultanato/k15/actions/runs/45397011333), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| IPv4 checksum / malformed ARP fields | Invalid IPv4-checksum SYN and malformed ARP fields still receive replies | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45396434723), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| TCP ACK-window | ACK offsets +1, +63, +64, +65535 and +65536 beyond `SND.NXT` all still get HTTP responses; same when `SND.NXT=0xFFFFFFC2` and +65536 wraps to `0x0000FFC2` | No HTTP payload for all offsets, including forced wrap | Same as first fix | [expanded TAP matrix](https://github.com/miSultanato/k15/actions/runs/45412713955), [forced-wrap matrix](https://github.com/miSultanato/k15/actions/runs/45413051340) |
| Peer MSS boundaries | Accepts MSS 0, 1, 100, 179, 180, 181, 215 and 216; sends 180-byte payloads (exceeds every peer MSS below 180) | No SYN-ACK for 0..215; accepts 216 and sends 180 | Same as first fix | [expanded MSS matrix](https://github.com/miSultanato/k15/actions/runs/45414487001) |
| SYN cookie time component | Delayed first ACK after 65s is accepted and following HTTP request processed | Same | Same | [three-way TAP test](https://github.com/miSultanato/k15/actions/runs/45410737525) |
| HTTPS methods | Lowercase `get` gets no HTTP response on bounty; `FOO` returns 405 | Lowercase `get` and `FOO` return 405 | Same as first fix | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| Missing Host header | GET without Host returns 200 | GET without Host returns 200 | GET without Host returns 400 | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| TLSInnerPlaintext without content type | Authenticated all-zero inner plaintext lengths 1, 2, 16, 255 and 300 are accepted; a following valid request is processed | Closes connection for all five lengths before following request | Same as first fix | [expanded three-way test](https://github.com/miSultanato/k15/actions/runs/45414676678) |
| ECDSA nonce boundaries | `n+1` aliases `1`; `n-1` verifies; `n` does not | Not compared | Not compared | [frozen signer test](https://github.com/miSultanato/k15/actions/runs/45393554079) |
| E820 BIOS signature | Frozen boot sector accepts a successful INT 15h response with wrong EAX signature | Rejects wrong signature | Same as first fix | [synthetic 16-bit BIOS differential](https://github.com/miSultanato/k15/actions/runs/45437038597) |

## Additional negative evidence

- The local upstream hostile-client regression suite passes, including malformed
  ClientHello cases. [#45382026675](https://github.com/miSultanato/k15/actions/runs/45382026675)
- On plain HTTP port 80, lowercase `get` and unknown `FOO` HTTP methods both returned
  HTTP 200 on all three tested images; this is distinct from the HTTPS parser. The
  reported method hang was not reproduced.
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

1. Add an emitted page-table/NX assertion for the short-site W^X layout; the
   runtime synthetic-RET differential is already reproduced.
2. If useful, test a stale SYN-cookie ACK after a synthetic connection is fully
   torn down. The existing 65-second delayed-first-ACK test passes on all three
   revisions and does not prove post-teardown replay.
3. Continue assessing the short-ARP stale-buffer disclosure only with synthetic
   data. Do not attempt to access production memory.

The ACK-window and peer-MSS boundaries (including 32-bit wrap, MSS 0 and MSS 1),
the TLSInnerPlaintext lengths 1/2/16/255/300, and the emitted boot hardening
checks have already been exercised locally. No private TLS key or scalar
recovery has been demonstrated.


Do not merge upstream development fixes into the frozen bounty branch. All
dynamic tests remain local, offline and synthetic-key only; no request is sent
to `15kb.org`.
