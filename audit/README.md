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
| `bounded-audit.yml` | Source invariants, assembly crypto tests, exact `ec.inc` reconstruction, Valgrind controls, QEMU framing and runtime nonce checks |
| `differential-framing.yml` | Same malformed ClientHello cases against frozen bounty and upstream fixed images; then upstream `tools/abuse.py` |
| `race-audit.yml` | Project's controlled cross-processor slot handover tests, `RACE=1,2,3` |
| `parser-fuzz.yml` | Same deterministic 20,000-case ClientHello fuzzer against bounty and fixed images |
| `memory-scan.yml` | Local synthetic-key CertificateVerify capture and one guest-RAM snapshot scan |

All are runnable from GitHub Actions. The race workflow uses a privileged,
isolated network namespace because GitHub-hosted runners disallow unprivileged
user namespaces.

## Main checks

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
- `test_clienthello_framing.py`: checks inner handshake-length and outer
  record-length mismatches against a local QEMU image.
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
