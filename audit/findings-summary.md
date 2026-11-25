# k15 bounty audit — executive status

**Updated:** 2026-11-25  
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
| Client Finished | Processes authenticated application data without receiving client Finished; corrupted Finished also ignored | Same behavior | Same behavior | [three-way omission/corruption/AEAD differential](https://github.com/miSultanato/k15/actions/runs/45482705312) |
| AEAD tag failure | Bad tag ignored; original valid same-sequence record processed | Same behavior | Same behavior | [first fix](https://github.com/miSultanato/k15/actions/runs/45394628025), [current main](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Dummy ChangeCipherSpec | Missing after normal ServerHello with 32-byte session ID | Sent after ServerHello | Sent after ServerHello | [normal path](https://github.com/miSultanato/k15/actions/runs/45417214217), [HRR path](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| HRR / second ClientHello | Completes HRR -> second ClientHello -> final ServerHello; sends 0 server CCS records | Same handshake; sends 1 server CCS record | Same as first fix | [OpenSSL wire-capture differential](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Short ARP stale buffer | 24-byte unicast ARP request returns prior synthetic victim MAC/IP suffix to a different sender, reproduced with `SMP=1` and `SMP=2` | Rejects stale-buffer reply in both configurations | Rejects stale-buffer reply in both configurations | [three-way single- and dual-CPU differential](https://github.com/miSultanato/k15/actions/runs/45561139141) |
| IPv4 checksum / malformed ARP fields | Invalid IPv4-checksum SYN and malformed ARP fields still receive replies | Same behavior | Same behavior | [latest three-way confirmation](https://github.com/miSultanato/k15/actions/runs/45561139141) |
| TCP ACK-window and invalid-ACK payload consumption | ACK offsets +1, +63, +64, +65535 and +65536 beyond `SND.NXT` still get HTTP responses; sequence-aware tests confirm full and partial invalid-ACK payloads advance receive state | Rejects invalid-ACK payload; consumes the following valid-ACK request from its original sequence | Same as first fix | [latest three-way differential, dual-CPU ARP and forced-wrap test](https://github.com/miSultanato/k15/actions/runs/45561139141) |
| Peer MSS boundaries | Accepts MSS 0, 1, 100, 179, 180, 181, 215 and 216; sends 180-byte payloads (exceeds every peer MSS below 180) | No SYN-ACK for 0..215; accepts 216 and sends 180 | Same as first fix | [assertive peer-MSS regression matrix](https://github.com/miSultanato/k15/actions/runs/45468109924) |
| SYN cookie time component | Delayed first ACK after 65s is accepted and following HTTP request processed | Same | Same | [three-way TAP test](https://github.com/miSultanato/k15/actions/runs/45410737525) |
| SYN-cookie ACK replay after FIN/FIN close | Replayed cookie ACK recreates a connection after 65s and a different-length HTTP request is processed; changed-source-port replay is rejected | Same observed behavior | Same observed behavior | [three-way 65s replay differential](https://github.com/miSultanato/k15/actions/runs/45443936657); [tuple-binding control](https://github.com/miSultanato/k15/actions/runs/45469926754) |
| HTTPS methods | Lowercase `get` gets no HTTP response on bounty; `FOO` returns 405 | Lowercase `get` and `FOO` return 405 | Same as first fix | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| Missing Host header | GET without Host returns 200 | GET without Host returns 200 | GET without Host returns 400 | [TLS differential](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| TLSInnerPlaintext without content type | Authenticated all-zero inner plaintext lengths 1, 2, 16, 255 and 300 are accepted; a following valid request is processed | Closes connection for all five lengths before following request | Same as first fix | [expanded three-way test](https://github.com/miSultanato/k15/actions/runs/45414676678) |
| ECDSA nonce boundaries | `n+1` aliases `1`; `n-1` verifies; `n` does not | Not compared | Not compared | [frozen signer test](https://github.com/miSultanato/k15/actions/runs/45393554079) |
| E820 BIOS signature | Frozen boot sector accepts a successful INT 15h response with wrong EAX signature | Rejects wrong signature | Same as first fix | [synthetic 16-bit BIOS differential](https://github.com/miSultanato/k15/actions/runs/45437038597) |
| Boot/build hardening | `apcount` is misaligned; GDT Accessed bytes are `0x9A/0x92`; E820 signature check and Makefile hostname guard are absent; runner hostname leaks into generated certificate SAN | Alignment and Accessed bits corrected; SMAP signature and `NAME` guard present; hostname excluded from certificate SAN | Same as first fix | [source, build, certificate and emitted-image differential](https://github.com/miSultanato/k15/actions/runs/45437038597) |

## Follow-up reviews (2026-11-25)

- `arp-short-frame-impact.md` now records the same 2,048-frame cross-sender stale-buffer disclosure on the frozen image with both `SMP=1` and `SMP=2`; both upstream revisions reject the short frame in both configurations. Run [45561139141](https://github.com/miSultanato/k15/actions/runs/45561139141) covers all three images and both CPU counts. This shows the issue is not limited to a single-CPU guest, but does not prove cross-CPU buffer access or quantify production race reliability.
- `tcp-ack-injection-impact.md` records the frozen-source `.odd -> .ak` ACK-window defect and attacker-model boundary. Run [45559938127](https://github.com/miSultanato/k15/actions/runs/45559938127) confirms two sequence-aware tests. With different HTTP requests at the same sequence, frozen response ACK `0x6789ac13` identifies consumption of the 69-byte invalid-ACK request; both upstream response ACKs `0x6789abfe` identify consumption of the 48-byte valid-ACK request instead. With an incomplete 42-byte prefix, the frozen image immediately ACKs `0x789abd09`, while both upstream images leave the receive sequence at `0x789abcdf`; retransmitting the full request then causes the frozen image to trim the overlapping prefix and accept only its six-byte suffix. Both tests pass in the forced-wrap build. This demonstrates TCP stream desynchronization under a synthetic established connection, not an off-path exploit or request smuggling.

## Follow-up reviews (2026-11-24)

- `tcp-sequence-window-review.md` records the current-upstream modular
  sequence admission interval and ACK advancement rules. The existing
  three-way ACK-window and forced-wrap runs already establish the frozen
  out-of-window ACK defect and upstream rejection. Exact client-sequence
  edges and FIN/RST combinations remain coverage gaps, not additional
  findings.
- `syn-cookie-reboot-review.md` now includes a hardened local QEMU reboot
  probe. The SYN MSS is encoded as a TCP option and queued pre-reset frames
  are drained before the new capture. The dynamic workflow still has no
  confirmed run result available; no pass is claimed.
- `tls-client-finished-review.md` records a successful three-way omission
  control: frozen bounty, first upstream fix and current upstream all process
  AEAD-authenticated application data without receiving client Finished.
  [run 45482705312](https://github.com/miSultanato/k15/actions/runs/45482705312).
  This is a shared TLS handshake-confirmation weakness, not a Finished-MAC
  forgery or evidence that an attacker without the application traffic key
  can inject data.
- `run_wx_pte_probe.sh` / `probe_wx_pte.py` now add an independent, read-only
  QMP inspection of the live page-table hierarchy. Three-way run
  [45484886594](https://github.com/miSultanato/k15/actions/runs/45484886594)
  passed: frozen bounty's SITE PTE is present/read-only/NX=0; first fix and
  current upstream are present/read-only/NX=1. All three report CR3=0x420000.
  Exact VA/PTE values are recorded in `wx-short-site-impact.md`.
- `test_tcp_rst_sequence.py` adds an exact/off-by-one RST sequence test. It
  uses the server's observed ACK as the reset sequence oracle, then verifies
  connection state by sending the remaining HTTP request. All three revisions
  pass: exact sequence resets the slot; offsets -1/+1 preserve it.
  [run 45484598190](https://github.com/miSultanato/k15/actions/runs/45484598190).
  This is expected behavior and closes a coverage gap, not a new finding.

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

- The SYN-cookie replay test is an observation, not a confirmed bounty finding: all three revisions accept the same cookie ACK after orderly FIN/FIN teardown, while rejecting that ACK after a source-port change. The upstream cookie is keyed to the client tuple and initial sequence with a boot-time secret, but has no visible time bucket or single-use counter. The isolated QEMU reboot probe `test_syn_cookie_reboot.py` / `syn-cookie-reboot.yml` has now passed in [run 45486557359](https://github.com/miSultanato/k15/actions/runs/45486557359) on all three pinned revisions: each guest reset produced a different SYN-cookie, rejected the pre-reset ACK and accepted a fresh ACK/HTTP request. This is QEMU-based synthetic evidence on a GitHub-hosted ephemeral runner, not a local NEO run. It confirms boot-reset key rotation in this test path, not time-based expiry or off-path forgery. Even if rotation is confirmed, this does not demonstrate off-path forgery, cross-tuple replay, application-authentication bypass or production reachability. See `syn-cookie-replay-observation.md`.

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

1. Extend TCP client-sequence coverage to exact admission-window edges and
   FIN combinations. The RST exact-match matrix passes on all three revisions:
   exact sequence resets the slot; offsets -1/+1 preserve it.
2. If useful, extend the ClientHello matrix to additional truncation offsets
   and record-prefix alignments. The one-byte inner-short and outer-short
   cases are already reproduced end-to-end.
3. Assess and communicate the shared client-Finished omission behavior with
   protocol-level impact boundaries kept explicit; it is present in all three
   tested revisions and is not yet shown to enable injection without the
   client application traffic key.

The short-site W^X regression is now confirmed at three independent levels:
emitted layout, the QEMU RET self-test, and a live PTE walk. The frozen image's
synthetic SITE page is present/read-only/NX=0; both upstream revisions are
present/read-only/NX=1. This is a real executable-page permission regression,
not proof of request-controlled writes, an arbitrary instruction pointer, or
remote code execution.

The client Finished omission is now dynamically reproduced on all three
revisions: each processes an AEAD-authenticated application record without
receiving client Finished. This is a shared TLS handshake-confirmation
weakness, not a Finished-MAC forgery or proof that a party without the
application traffic key can inject data.

The ACK-window and peer-MSS boundaries (including 32-bit wrap, MSS 0 and MSS 1),
the TLSInnerPlaintext lengths 1/2/16/255/300, TCP RST exact/off-by-one handling,
and emitted/live boot hardening checks have been exercised locally. No private
TLS key or scalar recovery has been demonstrated.

Do not merge upstream development fixes into the frozen bounty branch. All
dynamic tests remain local, offline and synthetic-key only; no request is sent
to `15kb.org`.


## RDRAND / nonce-pool rollback follow-up (2026-11-25)

- `rdrand-virtualization-review.md` separates native Intel shared-DRNG
  behavior, QEMU TCG guest randomness, KVM's configurable RDRAND interception,
  and the conditional effect of restoring full guest RAM.
- `nonce-pool-rollback-review.md` traces the exact frozen signer path:
  `sign` decrements `POOLN`, then loads the selected `POOLR` and
  `POOLK` entries from per-processor BSS. A full guest-memory snapshot/clone
  copies pending nonce material and its counters. Two branches consuming the
  same restored entry on different transcript hashes would meet the standard
  ECDSA nonce-reuse condition.
- This is a confirmed source-level precondition, not a confirmed production
  exposure. No evidence shows the bounty host is snapshotted/cloned or that
  two branches can expose signatures from the same restored entry.
- Existing run [45384777117](https://github.com/miSultanato/k15/actions/runs/45384777117)
  scans a QEMU RAM dump for the synthetic private scalar. It does not inspect
  nonce-pool counters/entries or perform a full VM-state restore. It must not
  be cited as a nonce-pool rollback test.
- Next validation remains a synthetic-only full VM-state fork/restore after
  pool preparation, between signatures, followed by distinct local
  CertificateVerify transcripts and synthetic-key nonce-reuse verification.
  No production traffic or infrastructure access is authorized or required.
