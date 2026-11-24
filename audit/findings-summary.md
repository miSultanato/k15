# k15 bounty audit — executive status

**Updated:** 2026-11-24  
**Target:** `FileSherlock/k15` bounty source, frozen at
`ab93479ebc7c85274c722b16897148286d1cfca3`  
**Audit harness:** public fork `miSultanato/k15`, branch `main`

## Bottom line

No private-key disclosure or practical key-recovery exploit has been found.

Several concrete defects are now reproduced against the frozen image. The most notable memory-safety-adjacent result is a **same-link stale-buffer disclosure through a 24-byte ARP request**: the frozen image returned a synthetic marker left in a previous receive buffer. The tested upstream image did not return that marker. This does not show that the disclosed bytes can be selected from private-key memory, or that the issue is reachable over the Internet.

The audit also reproduces TLS record-validation, TCP ACK-window and MSS defects. Some remain present in upstream framing-fix commit `a2d8893`; others are fixed there. The bounty target branch remains unchanged and pinned to its original commit.

## Confirmed differential evidence

| Finding | Frozen bounty image | Tested upstream image `a2d8893` | Evidence |
| --- | --- | --- | --- |
| ClientHello framing | Accepts five malformed cases (four inner lengths, one short outer record) | Rejects all five with fatal `decode_error` | [#45381737629](https://github.com/miSultanato/k15/actions/runs/45381737629) |
| Client Finished | Corrupted Finished followed by valid application data still gets HTTP | Same behavior | [#45394628025](https://github.com/miSultanato/k15/actions/runs/45394628025) |
| AEAD tag failure | Corrupt record is ignored; original valid same-sequence record is processed | Same behavior | [#45394628025](https://github.com/miSultanato/k15/actions/runs/45394628025) |
| Dummy ChangeCipherSpec | Missing after normal ServerHello with 32-byte session ID | Sent after ServerHello | [#45395033747](https://github.com/miSultanato/k15/actions/runs/45395033747) |
| Short ARP stale buffer | 24-byte ARP request returns a synthetic marker from the previous RX buffer | No marker reply observed | [#45397011333](https://github.com/miSultanato/k15/actions/runs/45397011333) |
| IPv4 checksum / malformed ARP fields | Invalid IPv4-checksum SYN and malformed ARP hrd/pro/hlen/plen still receive replies | Same behavior | [#45396434723](https://github.com/miSultanato/k15/actions/runs/45396434723) |
| TCP ACK-window | HTTP request with ACK 0x10000 beyond `SND.NXT` is processed | No HTTP payload observed | [#45397630737](https://github.com/miSultanato/k15/actions/runs/45397630737) |
| Peer MSS=100 | Completes handshake and sends a 180-byte data segment; SYN-ACK advertises MSS=1460 | Sends no SYN-ACK | [#45397630737](https://github.com/miSultanato/k15/actions/runs/45397630737) |
| ECDSA nonce boundaries | `n+1` aliases `1`; `n-1` verifies; `n` does not | Not compared | [#45393554079](https://github.com/miSultanato/k15/actions/runs/45393554079) |

## Additional negative evidence

- The local upstream hostile-client regression suite passes, including malformed
  ClientHello cases. [#45382026675](https://github.com/miSultanato/k15/actions/runs/45382026675)
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
