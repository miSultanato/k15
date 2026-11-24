# Upstream revision tracking

**Last checked:** 2026-11-24

## Pinned revisions

| Role | Repository ref | Commit |
| --- | --- | --- |
| Frozen bounty target | `FileSherlock/k15:bounty` | `ab93479ebc7c85274c722b16897148286d1cfca3` |
| First upstream framing fix used in early differential tests | `FileSherlock/k15` | `a2d8893261b2be15b44c86d6f4483d65820e943a` |
| Current upstream main comparator | `FileSherlock/k15:main` | `cb9f76a5a100c418bfcaeddcd4f137d30ab489d2` |
| Current upstream dev code parent | `FileSherlock/k15:dev` | `d335390feb3aee2a947277dfa792b86d14ea1828` |

The current `main` tip is a synchronization commit whose parent is the current
`dev` tip. Comparing `a2d8893` with current `main` shows 18 commits ahead
(17 through `d335390`, plus the main synchronization commit). Therefore, the
early `a2d8893` results must not be described as a complete assessment of
today's upstream.

## Relevant changes since a2d8893

The GitHub compare lists these source changes:

- `src/request.asm`: adds a Host-header check and returns a 400 response while
  closing the connection when a request lacks Host. This is relevant to the
  independent Host/HTTP parsing finding.
- `src/os.asm`: adds the Host-header token and changes code-alignment macros;
  the diff does not itself show a new fix for the previously reproduced
  short-ARP stale-buffer behavior.
- `src/tcp.asm`: removes a development-only two-packet reset hook.
- `src/poll.asm`: removes the matching development-only reset plumbing.
- `src/curves.asm` and `tools/ec.py`: substantial X25519/P-256 performance
  work. These changes need their own crypto regression and timing review; they
  are not assumed to fix the nonce-generation questions.

Other commits improve packaging, deployment, certificate handling, tests and
documentation. The current-main matrix is intended to determine which of the
previously reproduced behaviors persist after all these changes.

## Current-main comparison workflow

The following workflows now pin current main as a third target, separately
from the frozen bounty and the first upstream fix:

- `.github/workflows/differential-framing.yml`: ClientHello fields, TLS record
  handling and upstream hostile-client regression suite.
- `.github/workflows/ip-arp-boundaries.yml`: IPv4 checksum, ARP stale-buffer,
  TCP ACK-window, peer-MSS and HTTP method probes.
- `.github/workflows/parser-fuzz.yml`: reproducible ClientHello fuzz and
  malformed raw-frame fuzz.

All runs build locally in ephemeral GitHub Actions runners, use synthetic
certificates and keys, and do not contact the production service. The bounty
branch remains pinned and untouched.
