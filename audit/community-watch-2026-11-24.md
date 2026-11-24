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

- approximately 10,200 concurrent TLS 1.3 handshakes, up to 48 client
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
