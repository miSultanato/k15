# RDRAND virtualization and nonce-state rollback review

Date: 2026-11-24

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Executive result

Three distinct mechanisms must not be conflated:

1. **Native CPU RDRAND:** On Intel platforms the DRNG is documented as a hardware resource shared across cores/threads, not one independent generator per vCPU. Actual production vendor, CPU model and microcode are unknown.
2. **QEMU TCG RDRAND:** The local nonce workflow explicitly uses TCG (`KVM=0`). QEMU's TCG helper implements RDRAND through `qemu_guest_getrandom`, which obtains guest-visible randomness from QEMU's host crypto-random service (or deterministic/replay sources when those modes are enabled). This does not exercise the host CPU's RDRAND instruction.
3. **Guest-memory rollback:** The pending ECDSA nonce pool is ordinary guest BSS memory. A full VM memory snapshot/restore or clone can therefore duplicate already-generated, not-yet-consumed nonce material even if the underlying host RDRAND/OS CSPRNG is healthy and never rewinds.

The third item is a conditional operational risk, not a demonstrated property of the bounty host. No evidence currently shows that the production service is snapshotted, cloned, restored, or migrated in a way that duplicates live RAM.

## 1. Source-level processor state

The frozen source establishes the following:

- BSP boot calls `rand` with `ecx = 22` and destination `HKS` before it starts the APs (around `src/os.asm:828-832`). This fills the boot-time AES PRF round keys.
- `RLAST` is `NV + 208`; `POOLN` and `POOLFILL` are `NV + 64` and `NV + 68`.
- Before AP startup, the BSP copies the complete 2 MiB BSS image to each AP's private BSS (around `src/os.asm:870-920`). Thus every AP initially inherits the BSP's then-current `RLAST`, the same `HKS`, and the initial empty nonce-pool counters.
- After startup, each processor has a private BSS copy. The nonce pool, `RLAST`, curve registers and counters evolve independently in guest memory. `rand` compares a new qword only with that processor's local `RLAST`; there is no global cross-processor duplicate set.
- The first AP draw is compared against the copied BSP last qword. Subsequent AP draws are compared against that AP's own preceding draw.
- `stock` obtains four qwords per nonce and precomputes up to 64 nonce entries per processor. `POOLR`, `POOLK`, `POOLN` and `POOLFILL` are all part of the processor's BSS state.

This confirms that the *software bookkeeping* is per processor. It does **not** prove that the underlying hardware RNG is a separate stream per processor.

## 2. Native Intel DRNG model

Intel's DRNG guide describes the generator as a high-performance resource shared between multiple cores/threads. The DRNG hardware is connected to cores through an interconnect; per-core microcode services RDRAND requests. Intel describes instruction access as atomic and the generator as scalable across hardware threads.

Consequences for this audit:

- Treating each guest vCPU as an independent PRNG with its own reproducible stream is not justified for Intel hardware.
- Concurrent calls are requests to a shared hardware service. Scheduling can interleave which processor receives each successive output.
- The local per-processor `RLAST` check is not a cross-core duplicate detector. It can only reject an output equal to that processor's immediately previous output.
- A repeated output on a different processor would not necessarily be noticed by the local guard, but no real cross-core repeat has been observed and Intel's documented design does not predict one.

The actual bounty host vendor and model have not been established. Intel documentation is a vendor-specific reference model, not evidence that the production host uses Intel hardware.

## 3. Virtualization paths

### 3.1 QEMU TCG in this repository

`audit/run_qemu_nonce.sh` sets `KVM=0`. `tools/vm.sh` then selects QEMU's TCG path with `-cpu max`; it does not select `-accel kvm -cpu host`.

In QEMU's x86 TCG implementation, the RDRAND helper calls `qemu_guest_getrandom`. QEMU's guest-random implementation normally obtains non-deterministic bytes through its crypto-random routines; deterministic `-seed` mode uses a deterministic generator, and record/replay mode can record and replay guest-visible random bytes.

Therefore the existing 10,240-handshake QEMU TCG nonce test validates the server's nonce-pool and signing logic when supplied with QEMU-provided randomness. It does **not** measure native host RDRAND, the production hypervisor's RDRAND path, or the production host CPU's RNG behavior.

The separate `rdrand_host_probe.c` samples the GitHub Actions runner's exposed RDRAND instruction. The runner itself may be virtualized, so its underlying hardware/hypervisor path is not established. It is not the bounty host and is an independent data point only.

### 3.2 KVM / hardware virtualization

Intel VMX defines an `RDRAND exiting` execution control. If the hypervisor does not intercept the instruction, the guest can execute RDRAND in VMX non-root operation; if it does intercept it, the VMM is responsible for handling the exit. Guest CPUID exposure alone does not identify which execution path is used.

QEMU's `-cpu host` path exposes host CPU features, subject to KVM filtering. The repository's QEMU helper selects this only when KVM is requested and available. The current bounded workflow explicitly forces TCG, so it has no KVM comparison.

QEMU and libvirt documentation warn that host-passthrough CPU models are not generally safe for migration across heterogeneous hosts. This is a CPU-ABI compatibility warning; it is not evidence of RDRAND state duplication or RNG failure.

The production hypervisor, guest CPU model, RDRAND-exiting setting, migration policy and microcode are unknown. No claim about the live service's execution path is warranted. The CI workflow also installs QEMU from the runner's package repositories rather than pinning an exact QEMU build; the cited upstream helper describes the TCG design, while a future reproducibility improvement should record the installed QEMU version.

## 4. Full guest-memory snapshot / restore: conditional nonce-pool rollback

This is the most consequential new conditional observation.

The source stores pending nonce material in ordinary per-processor BSS:

- `POOLR`: precomputed ECDSA point coordinate material;
- `POOLK`: precomputed inverse-related nonce material;
- `POOLN`: number of unused nonces remaining;
- `POOLFILL`: pool construction position;
- `RLAST`: last qword observed by the local RDRAND guard.

The internal documentation also states that the private key is in the same memory and that unused nonces remain in the stock.

A **full RAM snapshot** taken while a pool is non-empty, followed by restoring that RAM image or running two clones from it, would duplicate the pending nonce entries and their pool counters. Both branches could then sign different TLS transcript hashes with the same ECDSA nonce. The usual ECDSA nonce-reuse algebra would recover the signing scalar from the two signatures.

This scenario does not require RDRAND itself to repeat after restore: the already-generated nonce and its precomputed signing material are copied as guest RAM. Restoring only the virtual disk is not enough.

Important distinctions:

- The local `tools/vm.sh` option `-drive ... snapshot=on` is a disk overlay. It is **not** a full guest RAM snapshot and does not exercise this scenario.
- A cold reboot that reinitializes BSS and generates fresh nonces is not the same as restoring a live RAM snapshot.
- A full memory snapshot or clone may be controlled by the hosting provider, but no such provider behavior has been verified for the bounty.
- The scenario needs two externally observable signatures from branches that consume the same pending nonce on different messages. A snapshot by itself is not a demonstrated remote attack.
- Restoring a single VM and exposing signatures from both the pre-restore and post-restore timelines could also create the required pair, if the pool state is restored and the same private key remains active.

**Classification: conditional infrastructure/rollback risk; not a confirmed bounty vulnerability.**

## 5. What existing tests establish

| Test | What it tests | What it does not test |
|---|---|---|
| `rdrand_host_probe.c` on Actions | Runner's native RDRAND output sample | Production host CPU or hypervisor |
| `run_qemu_nonce.sh` | TLS signatures and nonce uniqueness under QEMU TCG guest randomness | Native RDRAND or KVM passthrough |
| `make test` / assembly boundary tests | Curve arithmetic and deterministic nonce boundaries | Host RNG quality |
| Periodic-stream model | Adjacent-check limitation under chosen synthetic sequences | A real CPU producing such a sequence |
| Disk overlay (`snapshot=on`) | Disposable guest disk writes | RAM rollback or duplicated nonce pool |

The community report of 10,200 QEMU handshakes is also not enough to characterize the production RNG unless its exact accelerator and guest CPU execution path are known. The report did not publish a reproducible harness or raw nonce corpus.

## 6. Next safe validation

Priority order:

1. Ask for or establish the production guest CPU vendor/model, exposed CPUID RDRAND bit, hypervisor family, and whether the guest uses hardware-assisted virtualization or instruction emulation. Do not infer these from the server provider name.
2. If an isolated local KVM environment is available, compare the same frozen image under TCG and KVM `-cpu host`, recording QEMU version, host CPU model, guest CPUID and accelerator. This is a local environment comparison, not a proxy for the production host.
3. Build a **synthetic-only** RAM rollback regression: generate a non-empty nonce pool using a test key, save the full guest memory state, fork/restore it twice, and verify whether the two branches can emit different valid CertificateVerify signatures with the same nonce. Do not use the production key or service.
4. Keep disk-only snapshot tests clearly labelled as disk tests. Do not describe them as RNG-state or RAM-rollback tests.
5. Do not test the live service for snapshot behavior. Provider control-plane evidence or an authorized staging clone would be needed.

## Sources

- Intel DRNG Software Implementation Guide, §§3.1–3.4:
  https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
- Intel SDM, VMX secondary processor-based execution controls (RDRAND exiting):
  https://cdrdv2-public.intel.com/789585/326019-sdm-vol-3c.pdf
- QEMU x86 TCG RDRAND helper:
  https://github.com/qemu/qemu/blob/master/target/i386/tcg/int_helper.c
- QEMU guest-visible random implementation:
  https://github.com/qemu/qemu/blob/master/util/guest-random.c
- QEMU CPU model and host-passthrough migration guidance:
  https://qemu-project.gitlab.io/qemu/system/qemu-cpu-models.html
- libvirt host-passthrough migration warning:
  https://libvirt.org/formatdomain.html

No production traffic, host access, key access, migration, snapshot or load test was performed.


## 7. Latest bounded regression run

GitHub Actions run
https://github.com/miSultanato/k15/actions/runs/45489595284
completed successfully against frozen target
`ab93479ebc7c85274c722b16897148286d1cfca3`.

Observed results:

- Runner-exposed RDRAND probe: 10,000,000 qwords; zero adjacent repeats,
  zero distance-four repeats, zero duplicate qwords anywhere, and zero
  repeated four-qword tuples. The runner may itself be virtualized and is not
  the production host.
- QEMU TCG boot A: 10,240/10,240 completed handshakes, unique CertificateVerify
  r values and unique recovered nonces.
- QEMU TCG boot B: 1,024/1,024 completed handshakes, unique r values and
  unique recovered nonces.
- Cross-boot nonce fingerprint overlap: zero.
- The new static source guard passed, including the check that AP BSS copies
  occur after the BSP's HKS draw and contain the initial local RNG/pool state.

This is strong regression evidence for the frozen signer under QEMU TCG's
guest-random path and for one runner's exposed RDRAND instruction. It does not
measure the production CPU, production hypervisor, KVM passthrough, or full
guest-RAM snapshot/restore behavior.
