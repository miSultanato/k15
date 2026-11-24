# SYN-cookie key rotation across guest reset

Date: 2026-11-24

## Question

Does a SYN-cookie ACK captured before a guest reboot remain valid after the
server restarts, or does the cookie's boot-time key change make the old ACK
invalid?

## Source facts

Pinned current upstream source at
`FileSherlock/k15@cb9f76a5a100c418bfcaeddcd4f137d30ab489d2` shows:

- `src/os.asm` reserves `HKS` for the eleven AES round keys used by the
  SYN-cookie PRF: 176 bytes total.
- `src/conn.asm` computes the cookie with `prf`, which uses those round keys
  and the client's address/port tuple. The comments explicitly describe the
  keys as random and made at boot.
- `src/setup.asm` fills `HKS` by setting `EDI=HKS`, `ECX=22`, and calling
  `rand`. That writes 22 64-bit RDRAND values, i.e. 176 bytes.
- `src/curves.asm` implements `rand` with `RDRAND`; it retries when the
  instruction reports failure and halts with `UD2` if a value repeats the
  immediately preceding value stored in `RLAST`.

This establishes the intended boot-time key-generation path. It does not,
by itself, prove that a reboot actually regenerates a different key in the
runtime environment, nor that every possible reset path reinitializes all
relevant state.

## New dynamic regression probe

Files:

- `test_syn_cookie_reboot.py`
- `run_tap_syn_cookie_reboot.sh`
- `.github/workflows/syn-cookie-reboot.yml`

The workflow compares three exact revisions:

- Frozen bounty: `ab93479ebc7c85274c722b16897148286d1cfca3`
- First upstream fix: `a2d8893261b2be15b44c86d6f4483d65820e943a`
- Current upstream: `cb9f76a5a100c418bfcaeddcd4f137d30ab489d2`

For each image, the test:

1. Captures a SYN-ACK for one fixed synthetic IPv4 tuple and client ISN.
2. Uses QEMU's local human monitor to issue `system_reset`, preserving the
   TAP link and test process.
3. Repeats the same SYN with the same tuple and client ISN.
4. Requires a different server cookie. Up to three reset attempts are allowed
   to make an accidental 26-bit cookie collision negligible.
5. Replays the pre-reset ACK and sends a synthetic HTTP request; the old cookie
   must not produce an HTTP response.
6. Uses the post-reset cookie as a positive control; it must complete the
   request and return HTTP.

The probe uses raw Ethernet/TCP frames only on the ephemeral runner's private
TAP network. It contacts no production endpoint, uses no production key or
certificate, and uploads no artifacts.

## Status and interpretation

The workflow has been added to the public audit fork. Its runtime result is
pending at the time of this document; no success is claimed yet.

If it passes, it will establish that the tested QEMU boot/reset path rotates
the SYN-cookie secret sufficiently to invalidate the captured cookie, while
a newly issued cookie works. It will not establish that a reboot is a practical
anti-replay defense for a continuously running service, nor that captured
ACK replay is exploitable off-path. The existing same-boot 65-second replay
observation remains separate and is unchanged.

If it fails, inspect the exact failed stage before drawing a security
conclusion: a missing post-reset SYN-ACK, a cookie collision, old-cookie
acceptance, and fresh-cookie rejection are different outcomes.
