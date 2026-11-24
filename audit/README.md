# k15 bounty audit harness

This directory contains offline, reproducible checks against the exact source
revision offered by the k15 bounty.

## Scope and safety

- Frozen target: `FileSherlock/k15` commit
  `ab93479ebc7c85274c722b16897148286d1cfca3` (the `bounty` branch).
- QEMU tests boot locally built images and connect only to loopback or a private
  TAP network inside an ephemeral GitHub runner. The E820 boot-path test uses
  deterministic 16-bit emulation with synthetic BIOS responses.
- No request is sent to `15kb.org`; no production disk, certificate, key,
  wallet, account or infrastructure is accessed.
- Generated certificates, private keys, VM images and nonce captures remain
  in the ephemeral runner. Workflows upload no artifacts.
- Do not merge the upstream development fix into the frozen bounty branch.
  The upstream comparison is an audit control, not a change to the target.

## Workflows

| Workflow | Purpose |
| --- | --- |
| `bounded-audit.yml` | Native runner RDRAND probe, source invariants, assembly crypto tests, exact `ec.inc` reconstruction, Valgrind controls, QEMU framing and runtime nonce checks |
| `differential-framing.yml` | Compares frozen bounty, first upstream fix and current upstream main for TLS framing, transcript-faithful inner/outer-short ClientHello handshakes, record handling, HTTPS requests and full HRR/second-ClientHello behavior; runs each upstream hostile-client suite |
| `crypto-revision-check.yml` | Compares P-256 nonce boundaries, RNG source invariants, scalar-read paths and constant-time checks across all three source revisions |
| `race-audit.yml` | Project's controlled cross-processor slot handover tests, `RACE=1,2,3` |
| `parser-fuzz.yml` | Same deterministic 60,000-case ClientHello fuzzer (three seeds) plus raw Ethernet/IP/TCP frame fuzz against bounty, first fix and current main |
| `memory-scan.yml` | Local synthetic-key CertificateVerify capture and one guest-RAM snapshot scan |
| `wx-short-site.yml` | Three-way QEMU differential: execute a synthetic `RET` byte at the end of a one-file site to detect executable site pages |
| `ip-arp-boundaries.yml` | Deterministic IPv4/ARP checks, short-ARP stale-buffer probe, TCP ACK/MSS boundaries, delayed SYN-cookie ACK and forced 32-bit sequence-wrap probes |
| `boot-hardening-differential.yml` | Source/emitted-image comparison of AP counter alignment and GDT Accessed bits, synthetic BIOS E820 signature emulation, and Makefile NAME checks |
| `public-hygiene.yml` | Scans tracked public content for private-key PEM markers, generated certificate/build directories, private-key files, disk images, binaries and assembler listings |

All are runnable from GitHub Actions. The race workflow uses a privileged,
isolated network namespace because GitHub-hosted runners disallow unprivileged
user namespaces.

## Main checks

- `rdrand_host_probe.c`: samples the runner's exposed native RDRAND instruction,
  checking adjacent repeats, lag-four repeats, any repeated qwords and repeated four-qword tuples.
  This is only a host-runner data point, not a measurement of the production CPU.
- `nonce_cycle_demo.py`: mathematical demonstration that a periodic sequence
  can evade adjacent-equality checks and repeat ECDSA nonces. Synthetic only;
  it is not evidence that real RDRAND behaves this way.
- `check_rand_path.py`: source-level RNG and nonce-pool invariants.
- `check_key_read_path.py`: enumerates direct `R_D`/`REGS` accesses, VM
  register bounds, the `SIGN` program's use of `D`, and byte-for-byte
  reconstruction of generated `ec.inc`. Static audit only.
- `run_ct.sh`: runs the project's Valgrind constant-time test and confirms
  all six intentionally leaky controls are detected.
- `qemu_memory_scan.py`: snapshots one local QEMU guest-RAM image and searches
  for the expected Montgomery scalar encoding and the plaintext synthetic
  scalar in both byte orders. It does not inspect CPU registers, host memory,
  or transient states.
- `qemu_nonce_uniqueness.py`: captures local TLS 1.3 handshakes, decrypts the
  synthetic server's handshake flight using the client's temporary key log,
  verifies each CertificateVerify with the synthetic certificate key, and
  recovers the corresponding ECDSA nonce. It prints aggregate counts only.
  Optional one-way fingerprints allow comparison across separate QEMU boots.
- `run_tap_rawtest.sh`: runs the upstream raw Ethernet/IPv4/TCP malformed-frame
  fuzzer and verifies the QEMU guest remains alive and port-80 output stays bounded.
- `test_clienthello_framing.py`: checks inner/outer lengths, session IDs of
  33 and 255 bytes, compression method and legacy_version against local QEMU
  images; both oversized session IDs receive ServerHello on frozen bounty and
  fatal alerts on the two fixed upstream images.
- `test_malformed_clienthello_handshake.py`: constructs transcript-faithful
  inner-short and outer-short ClientHellos, verifies server CertificateVerify
  and Finished, sends an encrypted client Finished and HTTP request, and checks
  HTTP 200 on bounty versus fatal `decode_error` on both upstream revisions.
  The outer-short vector reuses its out-of-record `0x17` byte as the next
  record's content-type byte. `run_qemu_malformed_clienthello.sh` also runs a
  patched Go `crypto/tls` inner-short cross-check with CA and body validation.
- `test_tls_record_rejection.py`: corrupts a client Finished and an AEAD tag,
  then checks whether the local QEMU guest still processes valid app data.
- `test_dummy_ccs.py`: compares the normal ServerHello record sequence and
  elicits HelloRetryRequest. `test_hrr_second_clienthello.py` drives an OpenSSL client through a
  Go TLS 1.3 client through the second ClientHello and asserts the expected
  presence/absence of a dummy CCS on each pinned revision. The OpenSSL wire
  capture confirms two ClientHellos/two ServerHellos on all three revisions in [run 45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415).
- `test_https_request.py`: probes lowercase/unknown methods and missing Host
  over the TLS listener, exercising the decrypted HTTPS request parser.
- `test_ip_arp_validation.py`: sends synthetic IPv4 SYNs with valid/invalid
  header checksums and ARP requests with malformed hardware/protocol fields over TAP.
- `test_arp_short_frame.py`: primes RX buffers with full synthetic ARP requests,
  drains their normal replies, then checks whether a 24-byte ARP request discloses stale bytes. See
  `arp-short-frame-impact.md` for the exact eight-byte disclosure and threat-model limits.
- `test_tcp_ack_mss.py`: sends a data-bearing segment with an out-of-window ACK,
  tests peer-MSS boundaries, delays a first SYN-cookie ACK, then replays the same
  cookie after FIN/FIN teardown. The replay probe waits 65 seconds after teardown
  and compares the server ACK with the new request's end sequence.
- `check_current_rand_path.py`: checks the refactored current-main RDRAND-to-nonce path.
- `check_boot_hardening.py`: compares four source-level boot/build hardening changes between the frozen bounty, first upstream fix and pinned current main.
- `check_public_hygiene.py` and `test_public_hygiene.py`: narrow guardrail for this public fork; rejects tracked generated secret directories/files, private-key PEM markers, disk images, binaries and NASM listings. Synthetic marker/path tests check both detection and false-positive behavior. It is not a general-purpose secret scanner.
- `check_boot_binary.py`: checks the emitted `os.bin` and NASM listing for AP counter alignment and GDT descriptor Accessed bytes. It does not boot the image or exercise AP startup.
- `test_e820_signature.py`: executes the unchanged 16-bit E820 loop in Unicorn with synthetic valid and wrong-signature BIOS responses; compares the frozen boot sector with both upstream fixes. This isolates the signature gate and is not a real-BIOS compatibility test.
- `check_wx_layout.py`: derives the NX threshold from the emitted short-site image, NASM listing, DELTA and CODEPG source formula, then checks the final synthetic site byte's page. The three-way QEMU RET probe independently confirms runtime behavior; this check does not read live guest page-table memory.
- `run_qemu_abuse.sh`: runs the upstream hostile-client regression suite against
  the first upstream fix and current main, not against the frozen bounty image.
- `tools/racetest.sh`: exercises the project's deliberately synchronized
  RACE=1/2 timer-vs-slot ownership interleavings and RACE=3 bucket-boundary
  condition.

## Interpretation

A reproduced protocol-validation defect is not automatically a key disclosure.
The ClientHello framing discrepancy is confirmed on the frozen image; both the
first upstream fix and current main reject the same five malformed cases with
fatal `decode_error`.
We have not demonstrated successful TLS application-data exchange under a
mismatched transcript, memory corruption, private-key disclosure, or a
practical key-recovery exploit.

Runtime nonce uniqueness and controlled race tests strengthen the negative
evidence, but finite samples and selected interleavings are not mathematical
proofs of all hardware behavior or every possible SMP schedule. See
`community-watch-2026-11-24.md` for results, links, and third-party reports.


## Latest successful runs (2026-11-24)

| Evidence | Run |
| --- | --- |
| SYN-cookie replay after full FIN/FIN teardown, with a 65s delay and ACK-sequence proof on all three revisions | [45443936657](https://github.com/miSultanato/k15/actions/runs/45443936657) |
| Short-site W^X: emitted SITE page is executable only on frozen bounty; upstream maps it NX, confirmed by QEMU RET probe | [45439460997](https://github.com/miSultanato/k15/actions/runs/45439460997) |
| Synthetic BIOS E820: valid SMAP accepted by all; wrong-signature success counted only by frozen bounty | [45437038597](https://github.com/miSultanato/k15/actions/runs/45437038597) |
| HRR second ClientHello: two ClientHellos/two ServerHellos; frozen sends 0 CCS, both upstream images send 1 | [45436733972](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Oversized legacy_session_id 33 and 255 bytes: frozen accepts both; upstream images send fatal alerts | [45436733972](https://github.com/miSultanato/k15/actions/runs/45436733972) |
| Short-site W^X: frozen executes synthetic site byte; first-fix/current reset | [45409649945](https://github.com/miSultanato/k15/actions/runs/45409649945) |
| Authenticated all-zero TLSInnerPlaintext lengths 1/2/16/255/300: frozen processes following request; fixed/current close | [45414676678](https://github.com/miSultanato/k15/actions/runs/45414676678) |
| Go TLS normal-path CCS: frozen sends none; fixed/current send one after ServerHello | [45417214217](https://github.com/miSultanato/k15/actions/runs/45417214217) |
| Delayed first SYN-cookie ACK after 65s: accepted on all three pinned images | [45410737525](https://github.com/miSultanato/k15/actions/runs/45410737525) |
| ACK-window offsets +1, +63, +64, +65535, +65536: frozen accepts all; fixed/current reject all | [45412713955](https://github.com/miSultanato/k15/actions/runs/45412713955) |
| Forced-wrap ACK-window: SND.NXT=0xFFFFFFC2; frozen accepts +65536 wrap, fixed/current reject | [45413051340](https://github.com/miSultanato/k15/actions/runs/45413051340) |
| Peer MSS boundary: frozen sends 180-byte payload for MSS=100/179; fixed/current refuse 179..215 | [45413771856](https://github.com/miSultanato/k15/actions/runs/45413771856) |
| Boot hardening binary checks: AP alignment, GDT bytes, E820 instruction and hostname SAN | [45412245837](https://github.com/miSultanato/k15/actions/runs/45412245837) |
| Full bounded audit plus deterministic P-256 assembly nonce boundaries (`n-1`, `n`, `n+1`) | [45393554079](https://github.com/miSultanato/k15/actions/runs/45393554079) |
| Frozen QEMU TLS: corrupted client Finished and bad AEAD tag both ignored before valid HTTP | [45394182511](https://github.com/miSultanato/k15/actions/runs/45394182511) |
| Differential TLS record behavior: upstream framing-fix commit still processes valid HTTP after both malformed records | [45394628025](https://github.com/miSultanato/k15/actions/runs/45394628025) |
| Differential ClientHello framing and fixed-upstream hostile-client suite | [45394182367](https://github.com/miSultanato/k15/actions/runs/45394182367) |
| Differential dummy CCS: bounty omits it; upstream framing fix sends it | [45395033747](https://github.com/miSultanato/k15/actions/runs/45395033747) |
| Normal-path CCS plus HRR elicitation (post-HRR final flight still open) | [45398998479](https://github.com/miSultanato/k15/actions/runs/45398998479) |
| ClientHello session ID, compression and legacy_version differential | [45399706214](https://github.com/miSultanato/k15/actions/runs/45399706214) |
| Wrong handshake message type: bounty accepts; fixed image sends fatal `unexpected_message` | [45400449845](https://github.com/miSultanato/k15/actions/runs/45400449845) |
| HTTPS lowercase-method and missing-Host differential across all three revisions | [45402956609](https://github.com/miSultanato/k15/actions/runs/45402956609) |
| Three-way TLS comparison: bounty, first fix and current main | [45401470623](https://github.com/miSultanato/k15/actions/runs/45401470623) |
| Three-way TAP comparison: IPv4/ARP/TCP behavior on current main | [45401501930](https://github.com/miSultanato/k15/actions/runs/45401501930) |
| Three-way parser fuzz: bounty, first fix and current main | [45401525691](https://github.com/miSultanato/k15/actions/runs/45401525691) |
| TAP IPv4 checksum and ARP field matrix on bounty and upstream | [45396434723](https://github.com/miSultanato/k15/actions/runs/45396434723) |
| Short ARP stale-buffer differential: bounty discloses synthetic marker; upstream does not | [45397011333](https://github.com/miSultanato/k15/actions/runs/45397011333) |
| TCP ACK-window and peer-MSS differential | [45397630737](https://github.com/miSultanato/k15/actions/runs/45397630737) |
| Focused IPv4/ARP/TCP boundary workflow (checksums, short ARP, ACK, MSS) | [45397630737](https://github.com/miSultanato/k15/actions/runs/45397630737) |
| Cleartext port-80 method control (not the audited HTTPS parser) | [45400915976](https://github.com/miSultanato/k15/actions/runs/45400915976) |
| 60,000 ClientHello cases plus TAP raw-frame fuzz and deterministic IP/ARP probes | [45396434783](https://github.com/miSultanato/k15/actions/runs/45396434783) |
| Differential framing: five malformed cases accepted by bounty, rejected by fix | [45381737629](https://github.com/miSultanato/k15/actions/runs/45381737629) |
| Upstream hostile-client regression suite | [45382026675](https://github.com/miSultanato/k15/actions/runs/45382026675) |
| Controlled SMP slot races, RACE=1/2/3 | [45382612903](https://github.com/miSultanato/k15/actions/runs/45382612903) |
| 10M native RDRAND samples plus 10,240 + 1,024 QEMU nonce checks | [45387323167](https://github.com/miSultanato/k15/actions/runs/45387618913) |
| 60,000 ClientHello cases plus 3,191 raw frames on both source revisions | [45385140473](https://github.com/miSultanato/k15/actions/runs/45385140473) |
| Synthetic scalar guest-RAM snapshot | [45384777117](https://github.com/miSultanato/k15/actions/runs/45384777117) |

Start with `findings-summary.md` for the executive status, then see `community-watch-2026-11-24.md` for exact observations and third-party context. The end-to-end ClientHello/Finished client in `test_malformed_clienthello_handshake.py` passed the three-way differential in [run 45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415); its vectors and interpretation limits are documented in `framing-handshake-followup.md`. The independent auditor's 20 findings are reconciled against our actual test coverage in `independent-audit-coverage.md`.
