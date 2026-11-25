# ECDSA nonce-pool RAM rollback: source trace and validation boundary

Date: 2026-11-25

Target: frozen bounty source
`FileSherlock/k15@ab93479ebc7c85274c722b16897148286d1cfca3`.

## Executive result

**The source-level precondition for nonce reuse after a full guest-RAM rollback is confirmed. Actual snapshot/restore duplication and production exposure are not demonstrated.**

This review narrows the conditional risk recorded in
`rdrand-virtualization-review.md`. It traces the exact pool state consumed by
`sign`, identifies the state copied by a full VM snapshot, and distinguishes
the existing scalar-memory scan from a nonce-pool rollback test.

## Exact source path

### 1. Per-processor state is guest BSS

In `src/os.asm`:

- `BSSN = 0x200000 + LOW`; the runtime BSS base is `BSS`.
- `POOLR = BSS + 0x10000`.
- `POOLK = POOLR + 64 * 32 = BSS + 0x10800`.
- `NV = BSS + 0x0F200`.
- `POOLN = NV + 64 = BSS + 0x0F240`.
- `POOLFILL = NV + 68 = BSS + 0x0F244`.
- `RLAST = NV + 208 = BSS + 0x0F2D0`.
- The per-processor curve register file starts at `REGS = BSS + 0x0E400`; the private scalar is held in this guest-memory register area during signing.

The pool entries are ordinary writable guest memory, not state held exclusively
inside the CPU's hardware RNG.

### 2. Pool construction and consumption

The `stock` routine:

1. Draws four 64-bit words through `rand` for one 256-bit candidate.
2. Stores the nonce-derived inverse material in `POOLK`.
3. Computes and stores the point material in `POOLR`.
4. When all 64 entries have been prepared, batch-inverts the projective
   coordinates and nonce values, sets `POOLN = 64`, and resets
   `POOLFILL = 0`.

The comments identify `POOLR` as the x-coordinate material for (kG) and
`POOLK` as (R^2/k), the Montgomery representation consumed by the signer.
The raw nonce does not need to be regenerated to use an already prepared entry.

The `sign` routine then:

1. Reads `POOLN`.
2. If it is zero, calls `stock` and waits for preparation.
3. Decrements `POOLN` and writes it back.
4. Uses the resulting index to copy the corresponding 32-byte entry from
   `POOLR` into the curve register area.
5. Copies the matching entry from `POOLK` into the signing scratch registers.
6. Completes ECDSA using the current transcript hash and the private scalar.

Thus, after a full pool is prepared, the next signature consumes the same
indexed pair of precomputed values whenever the same `POOLN` state is restored.

### 3. AP memory is private but copied at startup

Before AP startup, the BSP generates `HKS` and then copies its complete 2 MiB
BSS image into each AP's private BSS region. At that moment the source comments
say no nonce stock has yet been made. After startup, each processor owns its
own pool and counters.

A **full guest-RAM snapshot** taken later includes all vCPU BSS regions,
including their pending `POOLR`/`POOLK` entries and `POOLN` counter. A clone
or restore of that snapshot duplicates those values. The disk-only
`snapshot=on` option in `tools/vm.sh` does not do this.

## Conditional consequence

If two execution branches resume from the same full-memory snapshot while
one or more nonce entries remain unused, and each branch signs a different
CertificateVerify transcript using the same restored pool entry and same
private key, the branches produce two ECDSA signatures with the same nonce
on different message hashes. The standard ECDSA nonce-reuse equations then
recover the private signing scalar.

The source-level state duplication precondition is therefore real. The
following operational facts remain unknown:

- whether the bounty service runs in a VM or another environment with
  full-memory snapshots/cloning;
- whether its operator ever restores or forks a live RAM image;
- whether such a snapshot can be taken at a quiescent point with
  `POOLN > 0`;
- whether two branches would both expose signatures made from the same
  restored pool entry.

No evidence currently establishes any of these conditions for the production
service. This is not a demonstrated remote exploit or a bounty finding.

## Existing evidence: do not overstate it

The prior QEMU test `qemu_memory_scan.py` uses the monitor's `pmemsave` to
dump guest physical RAM and searches for the synthetic private scalar in
plaintext and Montgomery form. Run
https://github.com/miSultanato/k15/actions/runs/45384777117
found the expected Montgomery encodings and no plaintext scalar encoding.

That test proves the synthetic key is present in guest RAM in the expected
representation at the captured instant. It does **not**:

- identify whether `POOLN` is nonzero at capture time;
- inspect `POOLR` or `POOLK` entries;
- restore the dump into a second VM;
- show that two branches consume the same pool entry;
- produce two signatures with different transcript hashes from one restored
  nonce.

Likewise, the 10,240 + 1,024 handshake uniqueness tests use QEMU TCG randomness
and test ordinary forward execution. They do not test RAM rollback.

## Safe validation plan

The next test should be split into explicit stages and use only the synthetic
certificate/key generated by the local build:

1. Add a read-only guest-RAM parser for the local test image that reports
   `POOLN` and `POOLFILL` for each processor and checks that the next
   `POOLR`/`POOLK` slot is populated. It must derive the runtime BSS base
   from the exact build layout rather than hard-code a site-dependent
   `LOW` value.
2. Use QEMU's VM-state migration/save-restore mechanism, not a disk overlay
   or `pmemsave` alone. QEMU documents migration as saving/restoring guest
   device state and RAM, with the same machine/device configuration required
   at restore. A practical fork test can save a migration stream to a file,
   preserve two identical copies, and load each into a separate destination
   VM with isolated TAP backends. Capture only after the pool is ready and
   between signatures.
   Reference: https://www.qemu.org/docs/master/devel/migration/main.html
3. Resume two isolated local branches from the same state. Give each branch a
   distinct synthetic ClientHello/transcript and capture the local
   CertificateVerify signatures.
4. Verify both signatures, recover their effective nonces using the synthetic
   test private key, and require equality. Then run the ECDSA recovery equation
   and confirm that the recovered scalar equals only the synthetic key.
5. Include negative controls: disk-only snapshot, fresh reboot, and two
   independently booted guests must not be reported as RAM rollback.

The workflow must not upload RAM dumps, keys, signatures, raw packet captures,
or nonce values. It should emit only aggregate pass/fail results and clean up
all temporary files. A failure to create/restore a full VM state is a harness
failure, not evidence that the risk is impossible.

## Classification

**Confirmed:** pending ECDSA nonce material, pool counters and private-key
working state reside in guest RAM; a full-memory snapshot necessarily copies
that state.

**Not yet tested:** actual full VM-state fork/restore and duplicate use of one
pool entry in two independent execution branches.

**Not established:** that the bounty host uses live VM snapshots, that an
operator can expose signatures from both branches, or that the condition is
remotely triggerable.

No production traffic, host access, key access, live snapshot, migration or
load test was performed.
