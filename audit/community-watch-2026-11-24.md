# k15 bounty: community intelligence and RDRAND hypothesis update

Date: 2026-11-24

Target remains the frozen `bounty` image at
`ab93479ebc7c85274c722b16897148286d1cfca3`. This note is research context
only. It does not change the target branch or authorize traffic beyond the
published bounty rules.

## Executive update

Community attention is real, but no public report found in this review claims
to have recovered the bounty key or moved the BTC. The strongest independent
technical report is negative evidence against an easy nonce attack: an auditor
reports about 10,200 local TLS 1.3 handshakes, 4,096 recovered nonces and
statistical testing without finding repetition or exploitable bias. This is
self-reported community evidence, not an independently reproduced artifact.

The RDRAND hypothesis remains mathematically valid but operationally unproven.
The relevant code boundary is narrow and now better characterized: each
processor has private BSS, including its own `RLAST`, nonce stock and pool
counters; `rand` checks each qword against the previous qword; `stock`
consumes four qwords per 256-bit nonce and precomputes a pool of 64.

## Community findings

### 1. Reddit: bounty announcement and early attempts

The bounty announcement on r/securityCTF (2026-11-20) identifies three
suggested attack surfaces: ECDSA nonces from RDRAND, the TLS record parser,
and processor slot handover. Replies report early dead ends on nonce reuse,
nonce bias and out-of-bounds reads.

Source:
https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/

### 2. Independent local nonce and crypto audit

A commenter on the same thread reports:

- approximately 10,200 TLS 1.3 handshakes, up to 48 client
  threads against an SMP=4 guest;
- every CertificateVerify `r` unique and every recovered nonce unique;
- two boots and 2,048 signatures with no cross-boot repetition;
- 4,096 recovered nonces and roughly 600 statistical tests, including
  modular intervals, bit-position tests and Hidden Number Problem-style
  lattice attempts, with no useful bias signal;
- a 229-case structured ClientHello parser exercise;
- a timing sweep over 36 synthetic key patterns without observed correlation.

The report explicitly says it used a local image, synthetic certificates and
keys, and did not contact the live service or possess its key. The post does
not provide a public repository or raw machine-readable result set in the
comment itself. Treat all counts and conclusions as reported, not reproduced.

Interpretation: this substantially lowers the priority of a generic
nonce-reuse/bias attack under ordinary emulated test conditions. It does not
rule out a rare host-specific RDRAND defect, hypervisor/CPU state anomaly,
or a discrepancy between the local test environment and the production
hardware.

### 3. Independent source audit (GitHub Issue #1)

Issue #1 reports a local, network-isolated QEMU audit of the pinned source.
It found no packet-triggered key disclosure, memory corruption, nonce reuse,
or secret-dependent branch/address path. It listed 20 lower-severity,
conformance, robustness and tooling findings.

The author replied that six fixes had landed on `main`; later notes mark
additional findings fixed, while some RFC/conformance items were left open
or deferred. The audit says `src/` at `ce74a13` was identical on `bounty`
at `ab93479`, but fixes subsequently made on `main` do not alter the
frozen bounty image.

Sources:
- https://github.com/FileSherlock/k15/issues/1
- https://github.com/FileSherlock/k15/commit/c4d40325ff25943d0c8271b4e0672500445d0be8

### 4. Other public analysis

A further Reddit comment describes a review of the public cross-curve
`bounty.proof` construction. The author reports that the proof's intentional
high-bit disclosure was already documented and that tests did not find a
statistical signal in the per-digit blinding values. This is another
self-reported negative result, not a formal proof or independent verification.

A separate community comment says an overnight Fable attempt did not find an
exploit. These are weak signals compared with reproducible test artifacts.

## What the source actually does

In the frozen `bounty` source:

- `RLAST` is at `NV + 208`, inside processor-local BSS.
- The per-processor memory model is documented in `docs/internals.md`:
  each processor gets its own BSS copy. Its curve registers, nonce stock,
  counters and `RLAST` are therefore not one global shared stream.
- `rand` executes `rdrand rax`, retries when CF is clear, compares the
  returned qword to `[RLAST]`, executes `ud2` on equality, then stores
  the qword as the new `RLAST`.
- `stock` calls `rand` with `ecx = 4`, so each candidate nonce consumes
  four consecutive qwords. It builds a stock of `NPOOL` (64) nonce
  candidates per processor, later consumed by `sign`.
- The nonce stock is prepared outside the immediate signature calculation;
  this makes ordinary signature timing a poor proxy for nonce-generation
  timing.

The check catches a constant stuck output (including the documented
all-ones failure mode) but is not a general health test for a sequence.
Any periodic stream with no equal adjacent qwords can evade the comparison.
A period-`p` stream repeats a four-qword batch after
`p / gcd(p, 4)` nonce batches. Thus periods 2 and 4 repeat every batch;
period 3 repeats every three batches. This is a conditional mathematical
property, not evidence that Intel/AMD RDRAND emits such a stream.

## Updated assessment

| Claim | Status | Reason |
|---|---|---|
| Repeated ECDSA nonce reveals the signing scalar | Confirmed cryptographic property | Standard ECDSA algebra |
| Adjacent-qword equality is not a complete RNG health test | Confirmed code property | It only rejects equality with the immediately previous qword |
| A periodic non-adjacent stream can repeat 256-bit batches | Confirmed mathematical property | Four qwords are consumed per nonce |
| The production CPU has emitted such a stream | Unconfirmed | No observation or host evidence |
| A remote client can induce or predict such a stream | Unconfirmed | No controllable trigger identified |
| The local test environment reproduces production RDRAND behavior | Unconfirmed | Community reports use local QEMU; hardware/backend details differ |

## Next work, in priority order

1. Keep the bounty branch immutable. All work remains in the fork's `main`
   and must not be deployed to `15kb.org`.
2. Preserve the synthetic model as a regression test, but expand it beyond a
   four-word cycle: periods 2, 3, 4, 5, 6, 7, 8 and 16 should all be checked
   for adjacent-check acceptance and eventual repeated four-qword batches.
3. Reproduce the community auditor's local methodology only if its harness or
   scripts become available. Ask for exact CPU model, QEMU accelerator
   (TCG/KVM), guest CPU flags, host kernel, number of boots, raw nonce export
   format and scripts. Do not treat an assertion without artifacts as proof.
4. Study RDRAND behavior from public CPU documentation and known errata,
   especially whether the production virtual CPU exposes hardware RDRAND,
   how migration/snapshot semantics apply, and whether any documented
   failure can produce a non-constant repeating sequence.
5. Analyze whether a remote client can reliably steer repeated handshakes to
   one processor using only the documented connection-affinity hash. Do this
   offline against source or a local VM; do not load-test the live service.
6. Keep parser, memory-layout and proof analysis as separate workstreams.
   Community audits have already covered much of the obvious key-disclosure
   surface; focus on reproducible gaps, not speculative exploit chains.

## Reproducibility boundary

The GitHub Actions run
https://github.com/miSultanato/k15/actions/runs/45369300643
passed the synthetic four-word model and `make test` on the frozen commit.
It did not exercise real RDRAND, run the community's 10,200-handshake test,
or contact the production server.

The expanded periodic-stream model is a software regression test only. A
passing result demonstrates the limitation of the adjacent-word predicate,
not a defect in any deployed CPU or hypervisor.


## RDRAND vendor documentation and historical failures

Intel's Software Developer's Manual describes RDRAND as output from a
cryptographically secure DRBG, reseeded from an on-chip entropy source, and
states that the design aims for statistically uniform, non-periodic and
non-deterministic output. It also says internal health tests should suppress
bad output by clearing CF. Intel recommends a bounded retry loop (example:
10 attempts), because CF=0 can occur transiently under demand and persistent
failure should not become an unbounded software loop.

Sources:
- Intel SDM, Volume 1, §7.3.17.1:
  https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf
- Intel DRNG Software Implementation Guide:
  https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html

Historical AMD incidents establish that RDRAND has not been infallible:

- In 2019, Ryzen 3000 systems were reported to return 0xFFFFFFFF repeatedly
  while reporting success; the widely discussed microcode/BIOS incident
  caused software that expected unique values to loop or fail.
- AMD family 15h/16h systems also had reports of RDRAND malfunction after
  suspend/resume due to BIOS resume handling; Linux responded by hiding the
  CPUID RDRAND feature on affected families in relevant configurations.

Sources:
- Ars Technica, October 2019:
  https://arstechnica.com/gadgets/2019/10/how-a-months-old-amd-microcode-bug-destroyed-my-weekend/
- Linux kernel mailing list patch, August 2019:
  https://lore-kernel.gnuweeb.org/lkml/776cb5c2d33e7fd0d2893904724c0e52b394f24a.1565817448.git.thomas.lendacky%40amd.com/T/

Relevance to k15:

- The documented all-ones failure is not a nonce-recovery route in this
  implementation: `RLAST` starts at zero, the first all-ones qword passes,
  the second identical qword triggers `ud2`. The outcome is machine failure,
  not a signature with a repeated nonce.
- A sequence that alternates or cycles through distinct qwords is not the
  historical all-ones failure. It would violate the documented RDRAND
  contract, but the current adjacent-value check would not detect it.
- The `jnc rand` retry is unbounded. CF=0 under transient backpressure is
  expected to be rare; a persistent failure can pin the processor in the
  retry loop. This is a liveness/availability observation, not a key
  disclosure primitive and not a reason to test the live service.
- The available historical AMD incidents concern older CPU families and
  specific firmware/resume conditions. They do not establish that the
  current Hetzner host, its CPU generation, or its hypervisor is affected.

Assessment: known RDRAND incidents justify retaining hardware RNG behavior
as a theoretical dependency to understand, but they do not materially
increase the probability of the specific non-adjacent periodic sequence
needed by our nonce-reuse hypothesis.


## Additional source-path detail: RNG calls outside the nonce pool

A closer call-site scan found three distinct uses of `rand` in the frozen
source:

- Boot consumes 22 qwords into `HKS` for the PRF round keys.
- Each TLS handshake consumes 4 qwords for the X25519 secret and another
  4 qwords for `ServerHello.random`.
- Each ECDSA nonce generated by `stock` consumes 4 qwords.

This matters when reasoning about arbitrary periodic streams: the simple
`p / gcd(p, 4)` repetition formula describes uninterrupted four-qword
`stock` batches. In a live processor stream, handshake draws can be
interleaved with nonce-pool generation and shift the phase for periods that
do not divide 8 (and the exact schedule depends on when the pool is filled
and consumed).

The specific period-4 counterexample remains aligned: the extra 8 qwords
consumed by the two handshake calls are a multiple of four, so every
four-qword chunk is still the same, regardless of whether it is used for
X25519, ServerHello.random or an ECDSA nonce. A period-4 stream would
therefore also predict repeated X25519 private scalars/public key shares and
repeated ServerHello.random values on a given processor, not just repeated
ECDSA nonces. Those are observable protocol values, but we have not
collected them from the live service.

The boot-time 22-qword draw changes the starting phase, not the period-4
property: any four consecutive outputs in a period-4 stream form the same
four-word block. The expanded script now models the 22-qword boot prefix
and the 8 extra handshake qwords for this period-4 case.


## Community status update (reviewed 2026-11-24)

The Reddit bounty thread has attracted several substantive independent
write-ups, not merely casual speculation:

- One auditor reports approximately 10,200 TLS 1.3 handshakes against a
  local SMP=4 QEMU image, 4,096 recovered nonces, two boots and 2,048
  signatures across boots, no repeated nonce or useful statistical bias,
  plus a 229-case ClientHello parser exercise. The author says the private
  scalar was absent from a 256 MiB guest-memory dump while the masked form
  appeared six times. This is a detailed self-report; no public harness,
  raw nonce corpus or independently reproducible artifact was linked in
  the comment.
- Another write-up maps the scalar to register D in the curve VM and says
  only the SIGN multiplication reads it. It describes the TLS record parser,
  table lookups and Valgrind constant-time checks as dead ends.
- A separate proof-focused review reports no usable leakage from the
  cross-curve Pedersen/DLEQ proof after follow-up sampling; the apparent
  first-run signal disappeared in a larger second sample.
- The project owner confirmed that several low-severity findings from
  Issue #1 were fixed on main, while the bounty branch remains the frozen
  deployment target. The owner also clarified that split ClientHello
  rejection is an intentional size/scope shortcut.

The bounty announcement is also being reposted by Hacker News aggregators
and AI/developer use-case sites, so visibility is increasing. Those
reposts are summaries, not additional security research or independent
findings.

Sources:
- Reddit bounty thread and auditor reports:
  https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/
- GitHub security/conformance audit:
  https://github.com/FileSherlock/k15/issues/1
- Project's current operating rules and bounty boundary:
  https://github.com/FileSherlock/k15/blob/main/CLAUDE.md
- Hacker News aggregator mention:
  https://geezer.io/p/3511

## Private-scalar read-path review (our static pass)

The pinned bounty source at ab93479 gives a more precise, finite
read-path question than the generic memory-disclosure search:

1. REGS is a processor-local BSS bank. R_D is register 14
   (REGS + 14*32), and the source has one declaration plus one explicit
   initialization copy into it.
2. Boot copies eight qwords from the generated constants into R_D.
   The generated value is the masked scalar d·R mod n, not plaintext d.
3. tools/ec.py defines the curve programs at build time. Of all the
   program bodies, only SIGN names register D, in the single operation
   T0 = X * D.
4. sign selects the fixed X_SIGN program. ecinit expands the compile-time
   bytecode into XP; .reg maps a register index with and eax, 15,
   then multiplies by 32 and adds REGS. This bounds a decoded register
   address to one of the 16 registers in the bank.
5. The packet-derived hash and nonce influence arithmetic inputs, but the
   inspected source does not use either as a VM program pointer or as a
   register index for the SIGN program.

This is a promising negative result, not a proof that the entire binary has
no secret-dependent read path. Remaining work is to connect the static
program-generation checks to the exact assembled ec.inc and to review
the VM's callers and all indirect address formation, including the table
selection paths. The source audit does not inspect the production image,
runtime register contents, or the hypervisor's memory.

The CI checker now makes the core invariants reproducible. Run
45372168669 passed the synthetic periodic-stream model, RNG call-site guard,
private-scalar read-path guard and upstream `make test` suite on the frozen
target commit ab93479.

A further run, 45373349450, reconstructed the exact textual `ec.inc` output
from the imported `tools/ec.py` program definitions using the same
serialization and offset rules as `tools/gen.py`. It covered 14 VM programs
and 1,816 unpacked bytes; the deterministic generated include has SHA-256
`02a6eb75314455ade2a5690b27ef85d7f4185a8585d96a078f1f188528a0d369`.
This is a deterministic source-derived manifest, not a byte comparison with
a production image or an assembled binary.

The offline proof check now validates the committed public cross-curve proof
and its address without connecting to 15kb.org or accessing a private key.
It does not compare the proof's P-256 point with a live TLS certificate.
None of these checks exercise real RDRAND hardware, the production VM, or
the live server.

Earlier runs 45371790632 and 45371845295 also passed the preceding
read-path checker revisions and make test.

## Revised priority

1. Review the next bounded-audit Actions result for the expanded
   R_D / D / X_SIGN / VM caller checks and the new packed-SITE read-path guard.
   The static review now covers the masked dR boot source, fixed comb callers,
   mask-only table selection, exact generated ec.inc comparison, and bounded
   HTTP path-to-response offsets; CI validation is still pending.
2. Keep the generated curve-program byte comparison against
   tools/ec.py in the audit. Do not attempt to recover or reconstruct the
   private scalar.
3. Deprioritize broad RDRAND cycle speculation unless a public hardware or
   hypervisor erratum matches the actual host model, or a reproducible local
   experiment produces a concrete anomalous stream.
4. Keep all dynamic testing local and bounded. No load, fuzzing, malformed
   handshake campaign, or denial-of-service testing against 15kb.org.


## Offline proof verification and key-generation boundary

The public `bounty.proof` is a 41,172-byte binary proof encoded as base64 in
the repository. Its verifier checks the 128 linked Pedersen commitments,
the aggregate commitment relation on both curves, and the Borromean ring
responses. This is useful to validate independently because it does not need
a TLS connection or any private material.

One detail narrows the meaning of the disclosed `flip` bit: `prove_xcurve`
supports both halves of the P-256 scalar range, but the actual `--gen` path
derives BIP-84 scalars repeatedly until `d < 2^255`. Therefore a proof
created by the documented bounty-generation path has `flip = 0` by
construction. The bit is not an extra unknown about this particular key; it
reflects a constraint already explicit in the public generator. The proof
still reveals only the two public points and the relation between them.

An offline CI verifier has been added to check the repository's exact proof
file, compare the verified Bitcoin address with its header, and report the
public P-256 and secp256k1 points. It must not be described as proving
knowledge of the private scalar or as a key-recovery method.


## Final bounded CI result (2026-11-24)

Run:
https://github.com/miSultanato/k15/actions/runs/45373486262

- Audit harness commit: `9391464c7407b64d0dd542f9f88fae060252e9e1`.
- Frozen target: `ab93479ebc7c85274c722b16897148286d1cfca3`.
- Result: success.
- Synthetic periodic-stream/ECDSA model: all configured periods passed.
- RNG source guard: all four call sites, per-CPU `RLAST`, and 64-entry nonce pool passed.
- Private-scalar read-path guard: `R_D` initialization, bounded register decode,
  fixed `X_SIGN`, table lookup bounds and source-to-generator linkage passed.
- Generated VM program manifest: 14 programs, 1,816 unpacked bytes,
  deterministic `ec.inc` SHA-256
  `02a6eb75314455ade2a5690b27ef85d7f4185a8585d96a078f1f188528a0d369`.
- Public proof: offline verification passed; version 1, `flip=0`,
  41,172 binary bytes; verified address
  `bc1qy53kjpg50e8scustvqk25ds3gh77578a7hj0g9`.
- Upstream crypto test: 70 signatures and 70 nonces passed.

The proof check validates the public proof's internal relation and derived
Bitcoin address. It does not fetch or compare the live TLS certificate.
The workflow checks out the exact bounty commit and does not upload build
images, certificates, private keys or generated secret-bearing files.

## Current conclusion

No public source reviewed through 2026-11-24 reports a successful key
recovery or bounty spend. Community write-ups are detailed but self-reported;
their raw datasets and harnesses are not public in the thread. Our additional
static checks strengthen the finite source-level argument around the scalar,
but do not prove the production hypervisor, CPU RNG or image contents.


## ClientHello framing discrepancy: confirmed, not yet a key leak

A community auditor and the project owner discussed a malformed-message case:
a ClientHello whose 24-bit handshake-message length is shorter than the
enclosing TLS record can still complete the handshake. The owner separately
confirmed that a ClientHello split across two TLS records is intentionally
rejected as a size/scope shortcut. These are distinct cases.

Static review of the frozen source confirms the short-length behavior:

- The TCP/TLS receive path assembles the record using the outer TLS record
  length at `HS_CH+3`, bounded by `CHMAX`.
- Once the record is complete, `.hello` calls `handshake` with
  `ecx = record_length - 5`: the complete record payload.
- `handshake` copies those bytes into the transcript and uses that same
  length as the ClientHello end pointer. It does not read or validate the
  ClientHello's own three-byte handshake length.
- The extension walk is bounded by the actual record payload end, not by the
  shorter handshake length declared inside the payload.

This is a confirmed framing/conformance discrepancy in the frozen branch.
It means bytes trailing the declared ClientHello can be interpreted as part
of that ClientHello, including as extension data. It is not, by itself, a
demonstrated out-of-bounds read or private-key disclosure: the walk is still
bounded by the assembled record buffer, and the bytes are supplied by the
same client. The independent auditor reports a 229-case structured
ClientHello test without finding an oracle or key-path disclosure, but the
raw corpus and harness were not published in the thread.

Status: retain as a bounded parser robustness issue, not as a confirmed
bounty exploit. A stronger claim would require a reproducible consequence
beyond accepting a malformed handshake length. Do not probe the live server;
any follow-up belongs in the local pinned-image harness.

Sources:
- Community audit discussion:
  https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/
- Frozen receive and handshake code:
  https://github.com/FileSherlock/k15/blob/bounty/src/os.asm
- Owner's current scope notes:
  https://github.com/FileSherlock/k15/blob/main/CLAUDE.md

## Additional community conclusions: proof and side-channel review

The November 22–23 discussion adds three useful negative results, all
self-reported and not independently reproducible from public artifacts:

- A timing sweep over 36 synthetic key patterns, 512 signatures per pattern,
  reportedly found identical minimum timings and no significant correlation
  between the secret's bit pattern and signing time. The author calls out a
  specification deviation and offered to send its details privately.
- A separate proof review generated repeated cross-curve proofs with fixed
  base-4 digits. An initial apparent bias disappeared in a larger fresh
  sample (250 proofs per digit); the author concluded the first trend was
  sampling noise.
- A Bitcoin-side analysis notes that the bounty proof itself publishes the
  secp256k1 public point, but not a signature made by the bounty scalar.
  The receive-only P2WPKH address and its funding transactions do not supply
  an ECDSA signature from the target key. The public point still leaves the
  ordinary discrete-log problem; the proof does not create a known
  cross-curve shortcut.

These reports reduce the expected value of broad timing, proof-blinding and
Bitcoin-chain speculation. They do not replace an independent proof review,
a reproducible timing harness, or an audit of the production image.

## CI scope expansion

The bounded workflow now runs `make all` after `make test` against the
same pinned bounty commit. This compiles the complete bootable disk image
using the test-generated local identity. The runner is ephemeral; no build
directory, certificate, private key or disk image is uploaded as an artifact.
This adds assembly/link/packing coverage, but still does not reproduce the
production certificate or inspect the running Hetzner image.


## Complete-image CI result (2026-11-24, follow-up)

Run:
https://github.com/miSultanato/k15/actions/runs/45376018641

- Audit harness commit: `db491b350a1577d5020df28bdf60f239565463e9`.
- Frozen target commit: `ab93479ebc7c85274c722b16897148286d1cfca3`.
- Result: success, including the new complete-image build step.
- The assembly crypto suite passed 70 signatures and 70 nonces.
- The generated bootable OS binary was 14,586 bytes; the packed site occupied
  727 bytes. The workflow then created `build/disk.img`.
- All static RNG, private-scalar read-path and public-proof checks passed.
- The runner uploaded no artifacts and was discarded after the job.

This is stronger build reproducibility than the preceding run: it proves
that the frozen source can be assembled and packed end-to-end with a
freshly generated test identity in CI. It does not prove that the generated
image is byte-identical to the deployed image, nor that the production
machine behaves like the runner.


## Upstream development branch: parser issue fixed outside the bounty image

A fresh branch comparison on 2026-11-24 shows:

- `bounty` remains frozen at `ab93479` (2026-11-20).
- Upstream `main` is at `c4d4032` (2026-11-21), with the six small fixes
  described in Issue #1.
- Upstream `dev` is at `d335390` (2026-11-24), 39 commits ahead and
  3 commits behind the frozen bounty branch. It contains substantial
  subsequent engineering work and is not the deployed bounty image.

Importantly, `dev` does address the ClientHello discrepancy described above.
Commit `a2d8893` added checks in `src/tls.asm` for:

- handshake message type exactly `1` (ClientHello), otherwise
  `unexpected_message`;
- session ID length no greater than 32;
- the 24-bit ClientHello handshake length exactly matching the bytes in the
  enclosing record, otherwise `decode_error`;
- compression methods exactly `01 00`, otherwise `illegal_parameter`.

The same commit adds regression cases in `tools/abuse.py`: wrong handshake
types, declared lengths one byte too short/long, a 64 KiB mismatch, trailing
bytes in the record, and malformed compression methods. It also tests that a
normal client still works afterward.

This is meaningful progress by the project owner, but it must not be
misattributed to the bounty deployment: the fix is in `dev`, not in the
frozen `bounty` commit. The later `dev` history also splits the monolithic
assembly source into subsystem files and adds DHCP/IPv6, publish automation,
and performance work. Those changes are outside our target and should not
be merged into the bounty branch.

Sources:
- Current upstream branches and commit history:
  https://github.com/FileSherlock/k15/branches
- Parser fix commit:
  https://github.com/FileSherlock/k15/commit/a2d8893261b2be15b44c86d6f4483d65820e943a
- Current development tip:
  https://github.com/FileSherlock/k15/commit/d335390feb3aee2a947277dfa792b86d14ea1828


## Valgrind taint-check reproduction (2026-11-24)

Run:
https://github.com/miSultanato/k15/actions/runs/45376601972

The workflow now installs the runner's packaged Valgrind and runs the
upstream `test/ct.c` against the assembly host object built from the frozen
bounty source:

- Normal cryptographic run: zero Valgrind errors.
- Deliberately bad control 1 (branch on shared secret): detected.
- Control 2 (branch on key-schedule secret): detected.
- Control 3 (branch on plaintext before sealing): detected.
- Control 4 (branch on decrypted record data): detected.
- Control 5 (branch on signature before publication): detected.
- Control 6 (index a table with a secret byte): detected.

All six negative controls were detected, so this is not merely a clean run
with a broken taint harness. The same CI run also passed the 70-signature
crypto suite, all static source checks and the complete bootable-image build
(14,586-byte OS binary, 727-byte site).

This independently reproduces the project's Valgrind constant-time check
against the frozen source with the system package, rather than downloading
the project's pinned Valgrind bundle. It is still a local host-build test:
it does not establish resistance to every microarchitectural side channel
or prove that the production CPU and hypervisor behave identically.


## Exact generated-byte comparison (2026-11-24)

Run:
https://github.com/miSultanato/k15/actions/runs/45377189394

The private-scalar checker now runs after `make test`, when the frozen
source's actual `target/build/ec.inc` exists. It reconstructs the expected
include from the imported `tools/ec.py` program definitions and the
serialization rules in `tools/gen.py`, then compares the generated file
byte-for-byte.

Result: pass. The actual generated `ec.inc` matches the source
reconstruction exactly. Its SHA-256 is
`69f0760299bf3e19693545c138007c4b02c6e0adbe350cdc94f80c6d307de88f`.
The comparison covers the 14 VM programs and 1,816 unpacked bytes.

The same run passed the Valgrind normal path and all six negative controls,
the 70-signature crypto suite, offline public proof verification, all
source-level key-read assertions and the full bootable image build. Final
result: success on audit harness commit
`3b117d6e9692e83a505a5753f7b08c5ae9eef5ab`, targeting the unchanged
`ab93479ebc7c85274c722b16897148286d1cfca3`.

This closes the specific source-to-generated-VM-include comparison. It does
not compare the resulting disk image with the production image, and it
does not inspect runtime or hypervisor memory.


## Local QEMU reproduction of the ClientHello framing discrepancy

Run:
https://github.com/miSultanato/k15/actions/runs/45377562293

The workflow now boots the complete image built from the frozen bounty source
under QEMU TCG (four virtual CPUs, user-mode networking, localhost-only port
forwarding). A test client generated a normal ClientHello, changed only its
internal 24-bit handshake length to be one byte shorter, retained the full
outer TLS record length, and sent it to the local guest.

Observed result:

- The frozen bounty image returned a TLS ServerHello.
- The malformed ClientHello was therefore accepted and parsed using the
  enclosing record's payload length.
- The test did not contact 15kb.org; QEMU and the client ran entirely inside
  the GitHub runner.
- The check establishes a reproducible protocol-framing discrepancy, not
  memory disclosure, a private-key leak, or a way to complete a useful
  attacker-controlled session.

The workflow run passed end-to-end, including the synthetic RNG model,
source checks, byte-for-byte generated `ec.inc` comparison, offline proof,
70-signature crypto suite, Valgrind with six detected negative controls,
full disk-image build, and this local QEMU test.

The upstream `dev` branch contains the corresponding rejection check and
regression tests (commit `a2d8893`); the bounty image remains frozen and
does not contain that fix.


## Unavailable third-party artefact

The Reddit thread also links an overnight Fable attempt at
https://pastebin.com/izRBKd02 and says it found no exploit. The Pastebin
page and its raw endpoint were inaccessible during this review, and search
did not surface a mirror. We therefore record only that the link was posted;
we have not read, validated or relied on its contents.


## Reproducible ClientHello framing test (2026-11-24)

The fork's bounded GitHub Actions run
https://github.com/miSultanato/k15/actions/runs/45377562293
booted the exact frozen bounty image under QEMU TCG and sent a locally
generated ClientHello with its inner 24-bit handshake length one byte shorter
than the actual handshake body. The image replied with a TLS ServerHello.
This is runtime evidence that the frozen image accepts that malformed
framing, not merely a static source inference.

The test was then expanded in commit
https://github.com/miSultanato/k15/commit/5b34a9d8651cb1d4104a051e7c702334f0e53184
to try four inner-length values against the same complete valid body:
zero, one byte short, one byte long, and the maximum 24-bit value. The outer
TLS record length remains correct in each case. The expanded test's CI result
is pending at the time of this note; do not treat the four-case matrix as
confirmed until the QEMU job completes successfully.

Scope: all probes run against 127.0.0.1 in an ephemeral GitHub runner. The
bounty source revision remains pinned to ab93479ebc7c85274c722b16897148286d1cfca3.
No request is sent to the production host. Acceptance of inconsistent
handshake framing is a protocol-validation/conformance finding; no memory
corruption, key disclosure, or practical remote exploit has been established.


### Important distinction: inner handshake length vs outer TLS record length

The QEMU regression above changes the ClientHello handshake message's own
24-bit length field while keeping the enclosing TLS record length correct.
It establishes that this frozen implementation does not enforce equality
between those two lengths. It does **not** reproduce the separate community
description of a TLS record whose outer length itself is short, nor does it
establish a transcript omitting bytes. The handshake path appears to use the
outer record payload length when copying/parsing the message; the transcript
question must be analyzed separately against the exact receive/reassembly
path before making that claim.

The upstream fix in
https://github.com/FileSherlock/k15/commit/a2d8893261b2be15b44c86d6f4483d65820e943a
adds exact handshake-length equality validation, along with type, session-ID
and compression-method checks. This is corroborating evidence that the owner
treated the inner-length discrepancy as a real validation defect. The fix is
on upstream development history, not in the frozen bounty commit.

Current assessment: reproducible TLS framing/conformance bug on the bounty
image; no demonstrated key disclosure, memory-safety violation, transcript
integrity failure, or bounty-winning exploit. Keep it separate from any
outer-record truncation/fragmentation hypothesis.


## Separate outer-record-length probe (confirmed)

A second, deliberately separate local QEMU probe was added in commit
https://github.com/miSultanato/k15/commit/1fde392f1819d55a6316c77a5c8c2ba5a2faab30.
It keeps the complete original ClientHello bytes on the TCP stream but makes
the enclosing TLS record length one byte shorter, leaving the final byte
outside that record. The frozen bounty image still replies with ServerHello.
This was reproduced in
https://github.com/miSultanato/k15/actions/runs/45381012445.

The source path corroborates the mechanism: the receive path copies only the
outer-record-declared number of bytes into `HS_CH`, calls `handshake` with
`record_length - 5`, then clears the connection's pending input length. The
extra byte in the TCP segment is not included in the ClientHello passed to
`handshake` and is discarded when the pending input length is cleared. Thus
the server processes a truncated ClientHello and forms its transcript from
the truncated payload, while a conforming client constructed the full body.
This confirms the framing/transcript discrepancy described by the community
auditor at the ServerHello stage. It does not show that the client can finish
the TLS handshake or exchange application data using the mismatched transcript.


### Confirmed framing behavior: precise scope

Two independent malformed-length behaviors are now reproduced in QEMU TCG:

1. The ClientHello's inner 24-bit handshake length can be zero, one byte
   short, one byte long, or 0xFFFFFF while the complete outer record/body is
   valid; all four are accepted.
2. The outer TLS record length can be one byte short while the complete body
   is present on TCP; the image processes only the record-declared prefix and
   still emits ServerHello.

Both are on the exact frozen bounty source. The second path means the
server-side transcript is constructed from a truncated ClientHello prefix.
We have not yet demonstrated successful completion of the TLS handshake,
a usable session, a key leak, or a memory-safety impact. These remain
protocol-validation/transcript-consistency findings, not a bounty-winning
key-recovery result.


## Differential QEMU validation of the upstream fix (confirmed)

The new workflow
https://github.com/miSultanato/k15/actions/runs/45381737629
builds and boots both source revisions independently under QEMU TCG:

- Frozen bounty: `ab93479ebc7c85274c722b16897148286d1cfca3`
- Upstream fix: `a2d8893261b2be15b44c86d6f4483d65820e943a`

It sends the exact same five malformed ClientHello framing cases to each
image, using localhost only. Results:

| Case | Frozen bounty | Upstream fix |
| --- | --- | --- |
| Inner length zero | ServerHello | fatal decode_error |
| Inner length one byte short | ServerHello | fatal decode_error |
| Inner length one byte long | ServerHello | fatal decode_error |
| Inner length 0xFFFFFF | ServerHello | fatal decode_error |
| Outer record length one byte short | ServerHello | fatal decode_error |

All ten assertions passed. Both images were built in the ephemeral runner;
no image, certificate, private key or build artifact was uploaded.

This is strong differential evidence that the upstream patch fixes the
specific framing-validation discrepancy on the tested source revisions.
It confirms rejection at the ClientHello parser, not a successful exploit
against the bounty version. It does not demonstrate private-key recovery,
memory corruption, or successful application-data exchange using a
mismatched transcript.


## Upstream hostile-client suite on the fixed revision (confirmed)

The differential workflow was extended to run the upstream
`tools/abuse.py` suite against the locally booted fixed image. Run:
https://github.com/miSultanato/k15/actions/runs/45382026675

The suite passed all reported checks, including:
- forged and replayed TLS records followed by successful normal requests;
- cipher-suite, X25519 share, session-ID and alert behavior;
- all new ClientHello type, length and compression checks;
- legacy_version normalization and ChangeCipherSpec behavior;
- 1,565 truncated or length-mutated ClientHellos, followed by successful
  normal handshakes;
- HTTP method handling, authenticated inner plaintext handling, and port 80
  request framing/pipelining.

This run tests the upstream fixed source only. The frozen bounty image is
covered by the separate five-case differential probe, not by claiming that
the full upstream suite passes on the old source.

## Community context (2026-11-24)

The public Reddit thread
https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/
contains independent self-reports of extensive local testing: approximately
10,200 handshakes and 4,096 nonces with no repeats/bias found, constant-time
timing sweeps, memory scans that did not find the plaintext scalar, and a
229-case ClientHello fuzz. These are third-party reports, not artifacts
independently reproduced by this audit. The same discussion identifies the
short outer-record ClientHello truncation/transcript discrepancy that our
QEMU tests now reproduce. The thread's participants do not report recovering
the bounty key.


## Cross-processor slot ownership race suite (confirmed)

The race matrix passed on the exact frozen bounty source:
https://github.com/miSultanato/k15/actions/runs/45382612903

- RACE=1 (timer paused before `hold` marks the slot in-use): the new
  connection takes the old slot; the timer recognizes the slot changed and
  does not continue sending to the vanished client.
- RACE=2 (timer paused after `hold` marks the slot in-use): the taker cannot
  claim it; the timer gives up/resets the old connection, then the new
  connection gets a slot.
- RACE=3 (the only free slot counted in a bucket is taken before the walk
  reaches it): the search remains inside the bucket; all six held port-80
  connections remain responsive.

Observed outcomes from the runner:
- RACE=1: the third new connection got in 24 s after the slot became eligible;
  the old client was not reset first.
- RACE=2: the thirteenth new connection got in 34 s after eligibility; the old
  client was reset immediately before the new connection took its slot.
- RACE=3: 16 TLS connections filled the bucket; all six held port-80
  connections remained responsive.

All three harnesses passed. This materially closes the concurrency gap noted
as not dynamically covered in the independent 2026-11-21 audit. It tests the
specific controlled interleavings and slot-boundary condition, not every
possible SMP schedule or all load/loss/reordering behavior.


## Runtime ECDSA nonce sampling with synthetic key (confirmed)

The expanded bounded audit run
https://github.com/miSultanato/k15/actions/runs/45383575122
captured and cryptographically verified local TLS 1.3 CertificateVerify
messages from the frozen bounty image, then recovered the corresponding
nonces using the synthetic P-256 private key generated inside the runner.

Results from one QEMU boot:
- 10,240/10,240 TLS handshakes completed.
- 10,240/10,240 CertificateVerify signatures verified against the synthetic
  certificate key.
- 10,240 distinct ECDSA `r` values.
- 10,240 distinct recovered nonces, treating `k` and `n-k` as equivalent.

A second independent QEMU boot produced another 1,024/1,024 verified
signatures and unique nonces. The test compared one-way fingerprints of
`(r, canonicalized k)` across the two boots: overlap was zero
(10,240 + 1,024 samples).

Only aggregate counts and one-way fingerprints were retained in the ephemeral
runner; no nonce, signature capture, key log, certificate or private key was
uploaded. This is finite-sample evidence of nonce uniqueness on QEMU TCG,
not proof of uniform distribution, real-hardware RDRAND behavior, or absence
of every possible bias. The synthetic key is unrelated to the bounty key.


## 20,000-case deterministic ClientHello fuzz on both revisions (confirmed)

The new parser-fuzz workflow
https://github.com/miSultanato/k15/actions/runs/45383690499
ran the project's own `tools/hellofuzz.py` with seed `20261124`, 20,000
mutated ClientHellos per image, under isolated QEMU/TAP networking.

Both images remained alive and served a verified normal TLS page after each
500 malformed inputs and after the full run:

- Frozen bounty `ab93479...`: 20,000 in 91 s; 7,035 ServerHello responses,
  4,425 alert 70, 4,341 alert 40, 2,467 HelloRetryRequest/key-share prompts,
  1,115 silent responses and 617 connection resets. Final result: `ok: and the server
  serves as before`.
- Upstream fixed `a2d8893...`: 20,000 in 103 s; 6,311 ServerHello responses,
  4,387 alert 70, 3,717 alert 40, 2,467? [see note below], 1,970 alert 50,
  1,114 silent responses, 361 connection resets, 88 alert 47 and 53 alert 10. Final
  result: `ok: and the server serves as before`.

The fuzzer is a robustness/memory-safety smoke test, not a proof of absence
of bugs. The answer counts are observations, not a strict cross-version
equivalence metric: server scheduling and the protocol's accepted/rejected
paths affect them. The key result is that neither image reset or stopped
serving during the 20,000 malformed inputs. The separate five-case
differential test remains the precise regression proof for the framing fix.


## Synthetic scalar guest-RAM snapshot (confirmed)

The isolated TAP/QEMU memory scan passed:
https://github.com/miSultanato/k15/actions/runs/45384777117

After 1,024 successful local TLS 1.3 handshakes, QEMU's monitor saved one
256 MiB guest physical-RAM snapshot. The scan compared the generated local
P-256 private scalar in plaintext (both 32-byte byte orders) with the expected
Montgomery representation `d * 2^256 mod n`.

Observed:
- Guest RAM scanned: 268,435,456 bytes.
- Plaintext synthetic scalar encodings found: 0.
- Expected Montgomery-form encodings found: 6.

This is consistent with the design: the guest image and register bank contain
the scalar in Montgomery form, not as a plaintext 256-bit value. The snapshot
was deleted after scanning and no memory image or key material was uploaded.

Limit: this is one point-in-time guest physical-RAM snapshot after local
synthetic-key handshakes. It does not scan CPU registers, QEMU host memory,
all transient execution states, or the production machine. It is not a proof
that no plaintext representation can ever exist in any execution path.


## Expanded 60,000-case ClientHello fuzz comparison (confirmed)

The three-seed fuzz run completed successfully on both source revisions:
https://github.com/miSultanato/k15/actions/runs/45385013034

For each image, the project fuzzer sent 20,000 mutated ClientHellos for each
of seeds `20261124`, `20261125`, and `20261126` (60,000 total per image).
After each batch the harness verified the QEMU guest remained alive and
served a normal TLS page. All six 20,000-case batches passed.

This broadens the earlier single-seed run. It is still a bounded parser
robustness test, not proof that every possible input is safe or that the
server has no key-disclosure path.


## Raw Ethernet/IP/TCP fuzz plus repeated ClientHello fuzz (confirmed)

The extended comparison completed successfully:
https://github.com/miSultanato/k15/actions/runs/45385140473

On each source revision the runner:
- sent 60,000 ClientHello mutations across seeds `20261124`, `20261125`
  and `20261126`;
- then sent 3,191 deterministic/mutated raw Ethernet, IPv4 and TCP frames;
- checked that the QEMU guest remained alive, port-80 output stayed bounded,
  and a normal TLS page was still served.

Both the frozen bounty image and the upstream-fixed image passed. The fixed
revision's raw-frame harness additionally reports that a short ARP frame gets
no answer; the bounty revision's harness predates that extra assertion.

This is bounded robustness and memory-safety smoke testing. It did not find a
crash or service loss under these inputs, but does not prove safety for every
packet, parser state, timing or hardware configuration.


## Native runner RDRAND probe (confirmed, non-production hardware)

The bounded audit run
https://github.com/miSultanato/k15/actions/runs/45386477988
also executed the `RDRAND` instruction directly on the GitHub runner CPU,
outside QEMU, for 1,000,000 64-bit samples.

Observed:
- Adjacent equal qwords: 0.
- Equal qwords at distance four: 0.
- Repeated four-qword tuples: 0 / 250,000.

The probe checks the specific adjacent-repeat and period-four patterns relevant
to the synthetic nonce-cycle hypothesis. This is a measurement of the runner's
exposed RDRAND implementation only; it is not the production host CPU and
cannot establish the behavior of Hetzner's hardware.


## Upstream branch and bounty status check (2026-11-24)

The upstream repository now has both `main` and `dev` at
`cb9f76a5`; this is 18 commits ahead of the ClientHello validation fix
`a2d8893`. The fix is therefore integrated into upstream main/dev. The
bounty branch remains at the frozen target
`ab93479ebc7c85274c722b16897148286d1cfca3`; our fork's `bounty` ref was
also checked and remains at that exact commit. No changes were made to it.

The owner's public bounty post still describes the challenge as live until
18 February 2027, with the explicit rules not to cause denial of service and
not to attack Hetzner or the owner's accounts:
https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/

That discussion contains independent local reports of approximately 10,200
TLS handshakes, 4,096 nonce samples, statistical/lattice checks, timing sweeps,
and a 256 MiB guest-RAM scan. The reported conclusions align with our
independent results: no nonce reuse or exploitable bias found, no plaintext
scalar in guest RAM, and no recovered key. The owner acknowledged the
ClientHello framing issue but described the fragmentation shortcut as
intentional and the framing discrepancy as outside the key-disclosure bounty.
These are public participant reports, not proof that the prize remains
unspent; we have not independently queried the Bitcoin address balance.


The upstream main/dev comparison also shows that the newer branch removed
`bounty.proof` and the related public proof/ceremony/monitor scripts
(`tools/bounty.py`, `tools/bounty_ceremony.sh`, `tools/monitor_bounty.py`,
`tools/public-proof.py`, `tools/proof-public.json`). Those files remain
available on the frozen bounty branch used for this audit. This is repository
cleanup/history, not evidence that the bounty was paid or closed.


## Expanded native runner RDRAND sample (confirmed)

The latest bounded audit run
https://github.com/miSultanato/k15/actions/runs/45387618913
increased the direct native-instruction probe from one million to ten million
64-bit RDRAND samples on the GitHub runner CPU.

Observed:
- Adjacent equal qwords: 0 / 10,000,000.
- Equal qwords at distance four: 0 / 9,999,996.
- Repeated qwords anywhere in the sample: 0.
- Repeated four-qword nonce tuples: 0 / 2,500,000.

The same run repeated the 10,240 + 1,024 QEMU nonce checks and cross-boot
fingerprint comparison (zero overlap), rebuilt the frozen image, and passed
the ClientHello framing regression. This remains a measurement of the runner's
exposed RDRAND implementation, not the production host CPU.


### Clarification on the reported completed handshake

The owner's Reddit reply says that a ClientHello whose stated length is shorter
than its record can still complete the handshake. The independent auditor also
describes a short first-record length and a transcript omitting dropped bytes.
The public wording does not unambiguously identify whether each participant
means the inner 24-bit handshake length or the outer TLS record length.

Our harness deliberately distinguishes those two cases:
- Inner handshake length changed, outer record and body intact.
- Outer record length one byte short, complete bytes still present on TCP.

For both cases our QEMU regression checks confirm ServerHello acceptance.
A purpose-built Python TLS 1.3 client is now committed in
`audit/test_malformed_clienthello_handshake.py`. It constructs both variants
before hashing: the complete malformed inner-length message, and the
outer-record prefix actually processed by the server. The excluded final
`0x17` byte is stitched into the next client Finished record as its TLS
content-type byte, preserving a valid TCP/TLS stream. It then verifies
CertificateVerify and Finished,
sends an encrypted HTTP request, and expects HTTP 200 on the frozen image;
the fixed images must reject both with fatal decode_error. A separate patched
Go `crypto/tls` client independently cross-checks the inner-short case and
compares the exact HTTP body.

This is a deliberately non-conforming client for the outer-short case: it
mirrors the server's truncated transcript. The implementation is wired into
the differential QEMU runner but awaits a new Actions result. Until that run
passes, successful end-to-end completion remains unconfirmed by our own test.
This is protocol-framing research, not a private-key disclosure path.


## SITE/key adjacency comment reviewed (2026-11-24)

A new community comment points out that key-related bytes precede the public
`SITE` region and asks whether a response read could extend backwards into
them. I checked the frozen `src/os.asm` request lookup and `geom`/`pick`
response path against `tools/pack.py`.

The request selects a prebuilt path record by bounded hash-table probing and
exact path comparison. That record supplies a prebuilt response number.
`geom` masks the response number to 15 bits, scales it by the fixed 16-byte
entry size, reads a packer-generated offset/length, and adds `SITE` to the
offset. `pick` only selects prepacked plain/compressed/304 forms. The packer
caps response entries at 32,767 and the site at 768 MiB. I found no request-
controlled negative offset or read-before-`SITE` path.

The new `audit/site-adjacency-review.md` records the source reasoning and
limits, and `audit/check_site_read_path.py` adds a CI guard for the request
lookup, response index, SITE-relative blob pointer and packer bounds. This is
a bounded static review, not a formal proof. The optional
`WXTEST` write/execute probe is a separate compile-time page-permission test;
the default `make all` path does not set `WXTEST`. This comment is therefore
an adjacency concern worth checking, not evidence of key disclosure.


## Community pulse: Reddit cross-posts and independent assessments (2026-11-24)

The original project announcement has spread beyond the initial post:

- `r/securityCTF`: the bounty announcement and technical discussion
  (https://www.reddit.com/r/securityCTF/comments/1y1fjej/200_in_bitcoin_if_you_can_get_the_tls_key_out_of/)
  has roughly 239 votes in the retrieved snapshot. Participants describe
  independent local audits, nonce sampling, parser review and the cross-curve
  proof. No participant reports recovering the key or claiming the bounty.
- `r/ClaudeAI`: the project showcase
  (https://www.reddit.com/r/ClaudeAI/comments/1y1fion/i_wanted_to_see_how_good_claude_is_at_sizecoding/)
  has roughly 833 votes in the retrieved snapshot. Discussion is primarily
  about sizecoding, the use of Claude Code, and the unusual bounty design;
  it adds no independently reproduced security finding.
- `r/asm`: a smaller technical showcase
  (https://www.reddit.com/r/asm/comments/1y1fl7t/a_14_kb_https_server_os_in_x8664_assembly_boot/)
  asks for assembly review but has little technical follow-up in the snapshot.
- A Hacker News aggregator listing
  (https://geezer.io/p/3511) shows no comments in the retrieved snapshot.

One detailed community comment again raised the fact that key-related image
bytes precede public `SITE` bytes. The targeted source review and CI guard
are recorded above in the SITE/key adjacency section and
`site-adjacency-review.md`. The other long-form participant reports largely
agree with our current boundary: substantial local testing, no demonstrated
key recovery, and no evidence that the published cross-curve proof leaks the
scalar beyond the intended public relation.

These are engagement snapshots, not security evidence. Vote counts and
comment activity change, and no balance check of the bounty address was
performed.


## Cross-sender unicast ARP reproduction completed (2026-11-24)

The focused three-way TAP run
https://github.com/miSultanato/k15/actions/runs/45466831548
completed successfully. The harness discovers the guest MAC, then primes the
frozen image with 2,048 valid unicast ARP requests from a synthetic victim
MAC/IP. A different synthetic sender sends the 24-byte request. The bounty
reply is addressed to the attacker but carries the victim's stale MAC suffix
and IPv4 address in the ARP target fields. Both the first upstream fix and
current upstream main pass the explicit reject-mode assertion.

This is a stronger reproduction than the earlier broadcast primer because
the prior victim request is unicast. Linux documents unicast ARP probes for
stale neighbor mappings through ucast_solicit:
https://man7.org/linux/man-pages/man7/arp.7.html

The test remains local, synthetic, single-processor and limited to eight
metadata bytes. It does not establish arbitrary memory disclosure, private
key exposure, multi-processor reliability or Internet reachability.


## SYN-cookie ACK replay after orderly FIN close (2026-11-24)

The expanded three-way TAP run
https://github.com/miSultanato/k15/actions/runs/45468109924
completed successfully on frozen bounty, upstream-fixed and upstream-current.
All three accepted the exact cookie ACK again after the first connection had
completed FIN/FIN teardown and a further 65-second delay. The replayed ACK
materialized a new connection, and a different-length HTTP request was
processed at the original client sequence number.

The first and current upstream revisions share the same `src/conn.asm`
blob. Its `prf`/`ckx` logic derives and verifies the cookie from the client
tuple, initial sequence and boot-time keyed hash; the cookie has no visible
time bucket or single-use counter. The expanded probe now also changes the
source port while replaying the same ACK: all three images reject that
cross-tuple attempt, then accept the original tuple after the 65-second wait.
A valid first ACK takes the `.miss -> .make` path when no connection slot
exists. This explains the observed same-tuple replay but does not, by itself,
establish a security defect.

Classification is deliberately conservative: reproducible stateless-cookie
replay property, not yet a confirmed bounty vulnerability. It reproduces on
all three revisions, requires the original tuple/cookie ACK or equivalent
knowledge, and does not demonstrate off-path forgery, cross-tuple replay,
application-auth bypass or production reachability. The test's old "RST
teardown" log label was inaccurate; the connection closes with FIN/FIN and
the label is corrected.

See `audit/syn-cookie-replay-observation.md`. Keep this separate from the
bounty-only ARP stale-buffer disclosure and ACK-window defects.


## IPv4 checksum and full-length ARP parser boundaries (2026-11-24)

The three-way TAP matrix also confirms that all revisions answer a SYN whose
IPv4 header checksum is intentionally invalid while its TCP pseudo-header
checksum remains valid. Full-length ARP requests with non-Ethernet hardware
type, IPv6 protocol type, and mismatched hardware/protocol lengths also get
replies on all three images.

The source explains the distinction. The IPv4 receive path enforces fixed
version/IHL, fragment, protocol, destination and length checks, then validates
the TCP checksum; it does not calculate the IPv4 header checksum. The ARP
path enforces the minimum 42-byte frame, request opcode and target address,
but does not validate every ARP metadata field. No security consequence was
shown for these full-length malformed requests. This is separate from the
frozen-only short-frame stale-buffer disclosure, which the upstream length
gate prevents.

See `audit/ipv4-arp-validation-review.md`. Keep these observations
low-priority and do not overstate them as confirmed vulnerabilities.


## Bounded audit CI result (2026-11-24)

The complete `k15 bounded audit` workflow passed:
https://github.com/miSultanato/k15/actions/runs/45460761523

The log confirms the expanded private-scalar path checks, byte-for-byte
reconstruction of the 14 VM programs / 1,816-byte generated include, the
packed-SITE read-path guard, the normal Valgrind run and all six deliberate
negative controls. The run also completed the finite two-boot nonce sample
(10,240 + 1,024 unique fingerprints) and the frozen-source TLS framing
probes. These are bounded CI results, not formal proofs or evidence of
private-key recovery.


The tuple-binding extension is now validated by the three-way run
https://github.com/miSultanato/k15/actions/runs/45469926754. Frozen bounty,
first upstream fix and current upstream all reject the same cookie ACK when
the source port is changed, then accept it again on the original tuple after
the 65-second FIN/FIN replay interval. All three matrix jobs completed
successfully. This confirms the replay is tuple-bound rather than a generic
reusable ACK.
