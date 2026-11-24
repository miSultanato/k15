# k15 bounty audit — executive status

**Updated:** 2026-11-24  
**Target:** `FileSherlock/k15` bounty source, frozen at
`ab93479ebc7c85274c722b16897148286d1cfca3`  
**Audit harness:** public fork `miSultanato/k15`, branch `main`

## Bottom line

No private-key disclosure or practical key-recovery exploit has been found.
The strongest confirmed issue is a TLS ClientHello framing-validation defect
in the frozen bounty image. The same five malformed cases are rejected with
fatal `decode_error` by upstream commit
`a2d8893261b2be15b44c86d6f4483d65820e943a`.

The bounty target branch remains unchanged and pinned to its original commit.
All dynamic testing is local, offline and synthetic-key only.

## Confirmed evidence

| Area | Result | Evidence |
| --- | --- | --- |
| ClientHello framing | Frozen image accepts four invalid inner lengths and one short outer-record length; fixed image rejects all five | [Differential QEMU run](https://github.com/miSultanato/k15/actions/runs/45381737629) |
| Upstream regression suite | Hostile-client suite passes on fixed image, including 1,565 length-mutated ClientHellos | [Abuse suite](https://github.com/miSultanato/k15/actions/runs/45382026675) |
| SMP slot races | RACE=1, RACE=2 and RACE=3 all pass on frozen image | [Race matrix](https://github.com/miSultanato/k15/actions/runs/45382612903) |
| ECDSA/RDRAND | 10,240 + 1,024 unique QEMU nonces with zero cross-boot overlap; 10M native runner RDRAND samples, zero adjacent/lag-four repeats, and 0/2.5M repeated four-qword tuples | [Expanded bounded audit](https://github.com/miSultanato/k15/actions/runs/45387618913) |
| Guest memory | One 256 MiB guest-RAM snapshot after 1,024 handshakes: zero plaintext synthetic-scalar patterns, six expected Montgomery-form patterns | [Memory scan](https://github.com/miSultanato/k15/actions/runs/45384777117) |
| ClientHello/raw-frame fuzz | 60,000 ClientHellos plus 3,191 malformed Ethernet/IP/TCP frames passed on each revision | [Expanded parser fuzz](https://github.com/miSultanato/k15/actions/runs/45385140473) |

## Interpretation

- The inner handshake-length mismatch is a protocol-validation defect. With
  the enclosing record intact, both peers can hash the same malformed bytes;
  no key disclosure has been shown.
- The short outer-record case makes the server process a truncated ClientHello
  and emit ServerHello. The owner and an independent auditor publicly report
  handshake completion under the truncated transcript; our current QEMU probe
  has not independently reproduced beyond ServerHello acceptance.
- The synthetic RDRAND-cycle demonstration proves only that adjacent-word
  comparison cannot detect every periodic sequence. It does not show that
  physical RDRAND repeats that way.
- Finite nonce samples and one RAM snapshot are evidence, not proofs of
  uniform randomness or absence of every transient plaintext representation.
- Controlled race tests cover the project's intended interleavings, not every
  possible SMP schedule.

## Next decision

Treat the framing issue as a reproducible protocol bug, not as a key-extraction
bounty result. Continue only if new evidence connects a defect to practical
recovery of the target private scalar. Do not merge upstream development fixes
into the frozen bounty branch, and do not test the production server.
