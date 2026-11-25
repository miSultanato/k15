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
- `src/start.asm` clears the BSS range from `BSSN` up to `TABV` on every
  entry to the boot path. `HKS` is at `BSS + 0x0F400` in `src/os.asm`, so the
  cookie round keys are inside that cleared range; `setup.asm` then calls
  `rand` to populate them before normal packet processing. This closes the
  static reset-path gap: a full guest reboot re-enters startup with zeroed
  HKS and generates a new key. It does not substitute for the dynamic QEMU
  replay test, which still needs a recorded runtime result.

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

The probe's frame builder now encodes the SYN MSS as a real TCP option
(including the TCP data-offset field), rather than appending option-looking
bytes as SYN payload. It also drains queued receive frames before each new
cookie capture, so a delayed pre-reset SYN-ACK cannot be mistaken for the
post-reset response.

The first runtime attempts exposed a harness issue, not a server finding:
the generic `tap.sh` launcher sources `tools/vm.sh`, whose QEMU command
includes `-no-reboot`. A monitor-triggered `system_reset` therefore caused
the QEMU process/monitor socket to disappear instead of leaving the same VM
running through firmware reboot. The dedicated
`run_tap_syn_cookie_reboot.sh` now creates the same isolated TAP/virtio
setup but deliberately omits `-no-reboot`, preserving the QEMU process and
TAP interface. The monitor client consumes the greeting prompt and waits for
the command-completion prompt before continuing. A diagnostic path records
QEMU status, CPU registers and network-device state if the post-reset SYN
still receives no SYN-ACK. These are harness corrections; they do not change
the security interpretation above.

The probe uses raw Ethernet/TCP frames only on the ephemeral runner's private
TAP network. It contacts no production endpoint, uses no production key or
certificate, and uploads no artifacts.

## Status and interpretation

**Dynamic QEMU result confirmed:** GitHub Actions run [45486557359](https://github.com/miSultanato/k15/actions/runs/45486557359) completed successfully on 2026-11-24. All three matrix jobs passed:

| Revision | Job ID | Pre-reset cookie | First post-reset cookie | Result |
|---|---:|---:|---:|---|
| Frozen bounty `ab93479ebc7c85274c722b16897148286d1cfca3` | 138773405033 | `0x082d0d81` | `0x04061781` | Old ACK rejected; fresh ACK accepted; HTTP processed |
| First upstream fix `a2d8893261b2be15b44c86d6f4483d65820e943a` | 138773404702 | `0xe88b5d41` | `0xefa82541` | Old ACK rejected; fresh ACK accepted; HTTP processed |
| Current upstream snapshot `cb9f76a5a100c418bfcaeddcd4f137d30ab489d2` | 138773405221 | `0xc6831cc1` | `0x3c7dba41` | Old ACK rejected; fresh ACK accepted; HTTP processed |

The logs confirm that QEMU acknowledged `system_reset`, each first post-reset cookie differed from its pre-reset value, the pre-reset ACK produced no HTTP response, and the fresh ACK completed the synthetic request. All three jobs used the same fixed synthetic tuple/client ISN. No generated certificates, private keys, VM images or nonce captures were uploaded.

**Execution environment:** `ubuntu-latest` resolved to a GitHub-hosted Ubuntu 26.04 runner; the workflow installed QEMU 10.2.1 and ran the guest in an isolated network namespace/private TAP. This is QEMU-based synthetic evidence, not a local NEO run. It contacts no production endpoint. If acceptance policy requires a locally hosted QEMU run specifically, that remains a separate local confirmation.

**Conclusion:** the tested QEMU boot/reset path regenerates the SYN-cookie key sufficiently to invalidate the captured pre-reset cookie, while a newly issued cookie works, on all three pinned revisions. This is not a confirmed bounty vulnerability or a clock-based expiry. It does not establish off-path forgery, cross-tuple replay, application-authentication bypass, production reachability, or that reboot is a practical anti-replay defense for a continuously running service. The same-boot 65-second replay observation remains separate and unchanged.
