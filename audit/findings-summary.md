# k15 bounty audit — executive status

**Updated:** 2026-11-24  
**Target:** `FileSherlock/k15` bounty source, frozen at
`ab93479ebc7c85274c722b16897148286d1cfca3`  
**Audit harness:** public fork `miSultanato/k15`, branch `main`

## Bottom line

No private-key disclosure or practical key-recovery exploit has been found.

Several concrete defects are now reproduced against the frozen image. A new short-site QEMU differential confirms a **W^X boundary failure**: with a one-file synthetic site ending in a `RET` byte, the frozen image executes that site byte and continues serving, while both tested upstream revisions fault before serving. The strongest network-memory result is a **same-link stale-buffer disclosure through a 24-byte ARP request**: the frozen image copies eight bytes from a preceding peer's receive-buffer contents into a reply addressed to a different peer. The latest test uses 2,048 valid unicast ARP requests from a synthetic victim, then a short request from a separate synthetic sender. The frozen image returns the victim's MAC suffix/IP; both tested upstream revisions reject the frame. This is narrow metadata disclosure, not private-key or arbitrary-memory disclosure, and does not establish Internet reachability. See `arp-short-frame-impact.md`.

The audit also reproduces authenticated TLSInnerPlaintext validation failure, TLS record-validation, TCP ACK-window and MSS defects. Some remain present in upstream framing-fix commit `a2d8893`; others are fixed there. The bounty target branch remains unchanged and pinned to its original commit. Current upstream main is pinned separately at `cb9f76a5a100c418bfcaeddcd4f137d30ab489d2`.

## Confirmed differential evidence

| Finding | Frozen bounty | First fix `a2d8893` | Current upstream main `cb9f76a` | Evidence |
| --- | --- | --- | --- | --- |
| Short-site W^X | Emitted final site byte is executable (`site_page=0x103 < CODEPG=0x104`); synthetic `RET` executes and guest continues serving | Emitted site page is NX (`site_page=0x104 = CODEPG=0x104`); guest faults before service | Same as first fix | [emitted-layout + three-way QEMU test](https://github.com/miSultanato/k15/actions/runs/45439460997) |
| ClientHello framing | Accepts five parser-level malformed cases; transcript-faithful inner-short and outer-short both complete TLS 1.3 and return HTTP 200 | Rejects both full-handshake vectors with fatal `decode_error` (alert 50), as well as the parser-level cases | Same rejection | [parser differential](https://github.com/miSultanato/k15/actions/runs/45401470623), [full transcript differential](https://github.com/miSultanato/k15/actions/runs/45460246415) |
| ClientHello fields | Accepts 33-byte and 255-byte session IDs, non-null compression and wrong handshake type; echoes legacy_version 0x0301 | Rejects both oversized session IDs and non-null compression; rejects wrong type; responds with legacy_version 0x0303 | Same as first fix | [three-way framing/HRR run](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Client Finished | Corrupted Finished followed by valid application data still gets HTTP | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| AEAD tag failure | Bad tag ignored; original valid same-sequence record processed | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Dummy ChangeCipherSpec | Missing after normal ServerHello with 32-byte session ID | Sent after ServerHello | Sent after ServerHello | [normal path](https://github.com/miSultanato/k15/actions/runs/45417214217), [HRR path](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| HRR / second ClientHello | Completes HRR -> second ClientHello -> final ServerHello; sends 0 server CCS records | Same handshake; sends 1 server CCS record | Same as first fix | [OpenSSL wire-capture differential](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Short ARP stale buffer | 24-byte unicast ARP request returns prior synthetic victim MAC/IP suffix to a different sender | Rejects stale-buffer reply | Rejects stale-buffer reply | [three-way unicast differential](https://github.com/miSultanato/k15/actions/runs/45466831548) |
| IPv4 checksum / malformed ARP fields | Invalid IPv4-checksum SYN and malformed ARP fields still receive replies | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45396434723), [current main](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| TCP ACK-window | ACK offsets +1, +63, +64, +65535 and +65536 beyond `SND.NXT` all still get HTTP responses; same when `SND.NXT=0xFFFFFFC2` and +65536 wraps to `0x0000FFC2` | No HTTP payload for all offsets, including forced wrap | Same as first fix | [assertive three-way TAP and forced-wrap matrix](https://github.com/miSultanato/k15/actions/runs/45468109924), [forced-wrap matrix](https://github.com/miSultanato/k15/actions/runs/45413051340) |
| Peer MSS boundaries | Accepts MSS 0, 1, 100, 179, 180, 181, 215 and 216; sends 180-byte payloads (exceeds every peer MSS below 180) | No SYN-ACK for 0..215; accepts 216 and sends 180 | Same as first fix | [assertive peer-MSS regression matrix](https://github.com/miSultanato/k15/actions/runs/45468109924) |
| SYN cookie time component | Delayed first ACK after 65s is accepted and following HTTP request processed | Same | Same | [three-way TAP test](https://github.com/miSultanato/k15/actions/runs/45410737525) |
| SYN-cookie ACK replay after FIN/FIN close | Replayed cookie ACK recreates a connection after 65s and a different-length HTTP request is processed | Same observed behavior | Same observed behavior | [three-way 65s replay differential](https://github.com/miSultanato/k15/actions/runs/45443936657); [expanded TAP run](https://github.com/miSultanato/k15/actions/runs/45468109924) |
| HTTPS methods | Lowercase `get` gets no HTTP response on bounty; `FOO` returns 405 | Lowercase `get` and `FOO` return 405 | Same as first fix | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| Missing Host header | GET without Host returns 200 | GET without Host returns 200 | GET without Host returns 400 | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| TLSInnerPlaintext without content type | Authenticated all-zero inner plaintext lengths 1, 2, 16, 255 and 300 are accepted; a following valid request is processed | Closes connection for all five lengths before following request | Same as first fix | [expanded three-way test](https://github.com/miSultanato/k15/actions/runs/45414676678) |
| ECDSA nonce boundaries | `n+1` aliases `1`; `n-1` verifies; `n` does not | Not compared | Not compared | [frozen signer test](https://github.com/miSultanato/k15/actions/runs/45393554079) |
| E820 BIOS signature | Frozen boot sector accepts a successful INT 15h response with wrong EAX signature | Rejects wrong signature | Same as first fix | [synthetic 16-bit BIOS differential](https://github.com/miSultanato/k15/actions/runs/45437038597) |
| Boot/build hardening | `apcount` is misaligned; GDT Accessed bytes are `0x9A/0x92`; E820 signature check and Makefile hostname guard are absent; runner hostname leaks into generated certificate SAN | Alignment and Accessed bits corrected; SMAP signature and `NAME` guard present; hostname excluded from certificate SAN | Same as first fix | [source, build, certificate and emitted-image differential](https://github.com/miSultanato/k15/actions/runs/45437038597) |

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

- Invalid IPv4 header checksums with valid TCP checksums, and malformed full-length ARP metadata, are accepted on all three revisions. Source review shows the IPv4 header checksum is not separately verified and the ARP metadata fields are not all checked. No security consequence was demonstrated; these are low-priority validation observations, distinct from the frozen-only short-ARP disclosure. See `ipv4-arp-validation-review.md`.

- The SYN-cookie replay test is an observation, not a confirmed bounty finding: all three revisions accept the same cookie ACK after orderly FIN/FIN teardown, while rejecting that ACK after a source-port change. The upstream cookie is keyed to the client tuple and initial sequence with a boot-time secret, but has no visible time bucket or single-use counter. The local test does not demonstrate off-path forgery, cross-tuple replay, application-authentication bypass or production reachability. See `syn-cookie-replay-observation.md`.

- The ARP result is a real, local stale-buffer metadata disclosure using
  synthetic victim/attacker identities and a unicast ARP primer. It is limited
  to eight bytes and one processor-local receive buffer; it is not evidence of
  private-key disclosure, arbitrary memory access, or Internet reachability.
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

1. If useful, extend the ClientHello matrix to additional truncation offsets
   and record-prefix alignments. The one-byte inner-short and outer-short cases
   are now fully reproduced end-to-end; this remains a framing defect, not a
   demonstrated key-recovery path.
2. The cross-sender unicast short-ARP differential is complete. Any further
   work must remain synthetic and local; do not attempt to access production memory.

The ACK-window and peer-MSS boundaries (including 32-bit wrap, MSS 0 and MSS 1),
the TLSInnerPlaintext lengths 1/2/16/255/300, and the emitted boot hardening
checks have already been exercised locally. No private TLS key or scalar
recovery has been demonstrated.


Do not merge upstream development fixes into the frozen bounty branch. All
dynamic tests remain local, offline and synthetic-key only; no request is sent
to `15kb.org`.
