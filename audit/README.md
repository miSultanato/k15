# k15 bounty audit harness

This directory contains offline, reproducible checks against the exact source
revision offered by the k15 bounty.

## Scope and safety

- Frozen target: `FileSherlock/k15` commit
  `ab93479ebc7c85274c722b16897148286d1cfca3` (the `bounty` branch).
- All dynamic tests boot locally built images under QEMU TCG and connect only
  to loopback or a private TAP network inside an ephemeral GitHub runner.
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
| `differential-framing.yml` | Same malformed ClientHello cases against frozen bounty and upstream fixed images; then upstream `tools/abuse.py` |
| `race-audit.yml` | Project's controlled cross-processor slot handover tests, `RACE=1,2,3` |
| `parser-fuzz.yml` | Same deterministic 60,000-case ClientHello fuzzer (three seeds) plus raw Ethernet/IP/TCP frame fuzz against bounty and fixed images |
| `memory-scan.yml` | Local synthetic-key CertificateVerify capture and one guest-RAM snapshot scan |

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
- `test_clienthello_framing.py`: checks inner handshake-length and outer
  record-length mismatches against a local QEMU image.
- `test_tls_record_rejection.py`: corrupts a client Finished and an AEAD tag,
  then checks whether the local QEMU guest still processes valid app data.
- `test_dummy_ccs.py`: checks the record immediately after ServerHello when
  ClientHello carries a non-empty legacy session ID.
- `test_ip_arp_validation.py`: sends synthetic IPv4 SYNs with valid/invalid
  header checksums and ARP requests with malformed hardware/protocol fields over TAP.
- `test_arp_short_frame.py`: primes RX buffers with a synthetic marker, then
  checks whether a 24-byte ARP request discloses stale bytes.
- `run_qemu_abuse.sh`: runs the upstream hostile-client suite against the
  fixed development image, not the bounty image.
- `tools/racetest.sh`: exercises the project's deliberately synchronized
  RACE=1/2 timer-vs-slot ownership interleavings and RACE=3 bucket-boundary
  condition.

## Interpretation

A reproduced protocol-validation defect is not automatically a key disclosure.
The ClientHello framing discrepancy is confirmed on the frozen image, and the
upstream fix rejects the same five malformed cases with fatal `decode_error`.
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
| Full bounded audit plus deterministic P-256 assembly nonce boundaries (`n-1`, `n`, `n+1`) | [45393554079](https://github.com/miSultanato/k15/actions/runs/45393554079) |
| Frozen QEMU TLS: corrupted client Finished and bad AEAD tag both ignored before valid HTTP | [45394182511](https://github.com/miSultanato/k15/actions/runs/45394182511) |
| Differential TLS record behavior: upstream framing-fix commit still processes valid HTTP after both malformed records | [45394628025](https://github.com/miSultanato/k15/actions/runs/45394628025) |
| Differential ClientHello framing and fixed-upstream hostile-client suite | [45394182367](https://github.com/miSultanato/k15/actions/runs/45394182367) |
| Differential dummy CCS: bounty omits it; upstream framing fix sends it | [45395033747](https://github.com/miSultanato/k15/actions/runs/45395033747) |
| TAP IPv4 checksum and ARP field matrix on bounty and upstream | [45396434723](https://github.com/miSultanato/k15/actions/runs/45396434723) |
| Short ARP stale-buffer differential: bounty discloses synthetic marker; upstream does not | [45397011333](https://github.com/miSultanato/k15/actions/runs/45397011333) |
| Differential framing: five malformed cases accepted by bounty, rejected by fix | [45381737629](https://github.com/miSultanato/k15/actions/runs/45381737629) |
| Upstream hostile-client regression suite | [45382026675](https://github.com/miSultanato/k15/actions/runs/45382026675) |
| Controlled SMP slot races, RACE=1/2/3 | [45382612903](https://github.com/miSultanato/k15/actions/runs/45382612903) |
| 10M native RDRAND samples plus 10,240 + 1,024 QEMU nonce checks | [45387323167](https://github.com/miSultanato/k15/actions/runs/45387618913) |
| 60,000 ClientHello cases plus 3,191 raw frames on both source revisions | [45385140473](https://github.com/miSultanato/k15/actions/runs/45385140473) |
| Synthetic scalar guest-RAM snapshot | [45384777117](https://github.com/miSultanato/k15/actions/runs/45384777117) |

Start with `findings-summary.md` for the executive status, then see `community-watch-2026-11-24.md` for exact observations and third-party context. The remaining end-to-end ClientHello/Finished experiment is specified in `framing-handshake-followup.md`. The independent auditor's 20 findings are reconciled against our actual test coverage in `independent-audit-coverage.md`.
