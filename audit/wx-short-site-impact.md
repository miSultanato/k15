# Short-site W^X finding: mechanism and impact boundary

Date: 2026-11-24

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Result

The short-site differential is a real page-permission regression in the frozen
image, but it is not by itself a remote code-execution exploit.

The harness builds a one-file synthetic site whose final byte is x86 `RET`
(`0xC3`), compiles the image with the project's own `WXTEST=4` self-test,
and lets boot finish before the self-test scans the site for that byte and
calls it. A page-permission fault resets the guest; a successful return lets
the guest continue to serve HTTP.

The three-way run
[45439460997](https://github.com/miSultanato/k15/actions/runs/45439460997)
observed:

| Revision | Final synthetic site byte | Runtime result |
| --- | --- | --- |
| Frozen bounty | Executable page | `RET` executes; guest remains alive and serves |
| First upstream fix | NX page | Execution faults; guest resets before serving |
| Current upstream main | NX page | Execution faults; guest resets before serving |

The independent emitted-layout check reconstructs the page threshold from
the source formula and NASM output. It verifies the final site byte's actual
virtual page relative to `CODEPG`; the QEMU self-test then checks runtime
behavior. The check does not read live page-table memory.

## Why the test is meaningful

The project's documented memory model says image code is executable and
read-only, while constants, the private-key block, certificates and site
are read-only and non-executable. The page boundary is intended to fall
between code and read-only image data, without padding bytes in the image.
See the upstream
[internal memory-layout documentation](https://github.com/FileSherlock/k15/blob/cb9f76a5a100c418bfcaeddcd4f137d30ab489d2/docs/internals.md).

The regression is visible in the emitted layout: for the frozen build the
last byte of the synthetic site falls on a page below the computed
`CODEPG` threshold; in the two fixed builds it falls on the threshold page
itself. The fixed source computes the executable boundary from the end of
the copied trampoline instructions (`xend`) and the image load displacement
(`DELTA`), rather than relying on the older codend-based boundary used by
the frozen target. The audit guard pins both formulas and refuses an
unexpected source-layout change.

The upstream W^X self-test also deliberately executes a `RET` byte in the
site, including a separate small-site case, and expects a fault. Its
`WXOPEN=1` control leaves the page open to prove that the test would
otherwise return and continue. See
[upstream tools/wxtest.sh](https://github.com/FileSherlock/k15/blob/cb9f76a5a100c418bfcaeddcd4f137d30ab489d2/tools/wxtest.sh)
and
[upstream setup self-test](https://github.com/FileSherlock/k15/blob/cb9f76a5a100c418bfcaeddcd4f137d30ab489d2/src/setup.asm).

## Security impact boundary

What this establishes:

- At least one page containing bytes from the frozen image's site is
  executable, contrary to the intended W^X layout.
- A byte already present in the built site can be executed by the image's
  boot-time self-test.
- The first upstream fix and pinned current upstream both place this
  synthetic site's final byte on an NX page and fault as expected.

What it does **not** establish:

- A network client can write to the site or modify the image.
- A request can choose an instruction pointer or trigger execution of
  request-controlled bytes.
- The site response path can read backwards into the preceding key block.
- Private-key disclosure, arbitrary memory access, control-flow hijack,
  persistence, or practical remote code execution.

The site is part of the image and is served as read-only data. Making a page
executable is a meaningful defense-in-depth and isolation failure, but
execution still requires a control-flow path to that page and useful
instructions already present there. The synthetic `RET` demonstrates the
permission state, not an attacker-controlled payload or a usable exploit
chain.

Keep this finding separate from the SITE adjacency review, the short-ARP
stale-buffer disclosure, and the TLS/TCP parser findings. No production
endpoint or credential was used.

## Reproduction

The fork's bounded three-way workflow is
[wx-short-site.yml](../.github/workflows/wx-short-site.yml). It builds each
pinned source revision locally, checks the emitted layout with
`audit/check_wx_layout.py`, then boots a local QEMU image with the
`WXTEST=4` site-execution probe. It uploads no artifacts.

