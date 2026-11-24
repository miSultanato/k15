# Coverage matrix: independent audit findings vs our bounded work

Date: 2026-11-24

Frozen bounty target: `ab93479ebc7c85274c722b16897148286d1cfca3`.

This document reconciles the independent 20-item audit with the checks in
`miSultanato/k15`. It deliberately distinguishes (a) owner-reported upstream
fixes, (b) checks we have run on our local frozen image, and (c) items not yet
covered. An upstream fix is not evidence that the frozen bounty image is fixed.

Independent audit:
https://github.com/FileSherlock/k15/issues/1

Owner's public fix notes:
https://github.com/FileSherlock/k15/issues/1#issuecomment-7061816714
https://github.com/FileSherlock/k15/issues/1#issuecomment-7081448356

## Reconciliation

| # | Finding | Upstream owner status (reported) | Our bounded evidence | Remaining gap |
|---|---|---|---|---|
| 1 | Site bytes may share executable page (W^X) | Fixed in the tested upstream revisions | Three-way QEMU differential [run 45409649945](https://github.com/miSultanato/k15/actions/runs/45409649945): a one-file synthetic site ends in `RET`; the frozen image stays alive and serves it after `WXTEST=4` executes the last site byte, while first-fix and current upstream reset before serving | Keep the test pinned; strengthen it with an emitted-image page-table/NX assertion if practical. The current runtime result demonstrates executable site data in this short-site layout, not arbitrary code execution over the network |
| 2 | TCP data accepted without acceptable ACK | Fixed in both `a2d8893` and current upstream main | TAP differential: after a valid handshake, an HTTP request with ACK 0x10000 beyond SND.NXT gets an HTTP response on bounty; both upstream images produce no HTTP response | Expand ACK matrix across below/equal/inside/above window and 32-bit wraparound |
| 3 | Session ID >32 and length wrap | Fixed in both `a2d8893` and current upstream main | TAP/QEMU differential: 33-byte legacy_session_id gets ServerHello on bounty; both upstream images send fatal `decode_error` | Add sid=255 and length-wrap boundary cases |
| 4 | Lowercase HTTP method may hang | Fixed in tested upstream `a2d8893` and current main | TLS 1.3 differential: lowercase `get` gets no HTTP response on bounty; both upstream images return 405. Unknown `FOO` returns 405 on all three | Keep the lowercase-method regression and test other case variants |
| 5 | ServerHello echoes legacy_version | Fixed in both `a2d8893` and current upstream main | QEMU differential: ClientHello legacy_version 0x0301 is echoed as 0x0301 by bounty; both upstream images send ServerHello legacy_version 0x0303 | Add more malformed legacy_version values and assert 0x0303 or fatal alert |
| 6 | Handshake type/declared length unchecked | Fixed in both `a2d8893` and current upstream main | Frozen image treats a type-2 handshake message as ClientHello and emits ServerHello; both upstream images return fatal `unexpected_message` (alert 10). Length mismatches are also rejected | Retain exact type/length cases and assert fatal alert class/description |
| 7 | legacy_compression_methods unchecked | Fixed in both `a2d8893` and current upstream main | QEMU differential: non-null compression method gets ServerHello on bounty; both upstream images send fatal alert 47 (`illegal_parameter`) | Add compression vector length/value matrix and require fatal alert |
| 8 | Dummy ChangeCipherSpec absent with non-empty session ID | Present in both `a2d8893` and current upstream main | QEMU differential: 32-byte legacy_session_id; bounty's record after ServerHello is type 23, both upstream images use type 20 | Add HelloRetryRequest-path coverage and test additional non-empty session_id lengths |
| 9 | Client Finished not verified | Not listed as fixed in cited notes | Local end-to-end differential: corrupt client Finished, then send valid app data; bounty, `a2d8893` and current main all return HTTP | Determine whether an attacker without traffic keys can reach this state; do not equate it with key disclosure |
| 10 | Bad AEAD tag does not terminate connection | Not listed as fixed in cited notes | Local end-to-end differential: corrupt AEAD tag, then replay the original valid same-sequence record; all three images process the valid record | Determine protocol/security impact; no traffic-key forgery is demonstrated |
| 11 | Inner plaintext with no content type accepted | Fixed in `a2d8893` and current main | [Corrected three-way QEMU test 45409977046](https://github.com/miSultanato/k15/actions/runs/45409977046): authenticated 1-byte and 300-byte all-zero inner plaintext records are followed by a valid request; frozen bounty processes it, while both upstream revisions close without processing it | Extend to additional padding lengths and confirm fatal-alert/connection teardown semantics; synthetic local keylog material only |
| 12 | Missing Host / absolute-form HTTP handling | Reported as not security-relevant by owner in earlier note; no fix recorded | Not tested in current bounded suite | Treat as HTTP conformance only; decide whether worth byte budget |
| 13 | TCP segment may exceed peer MSS below 216 | Fixed in both `a2d8893` and current upstream main | TAP differential: peer MSS=100; bounty advertises MSS=1460 and sends a 180-byte data segment; both upstream images send no SYN-ACK | Extend boundary matrix to MSS values 0..215 and confirm refusal/segment limits |
| 14 | ISN/cookies lack clock component | No fix recorded in cited notes | [Source review](cookie-time-component-review.md) finds boot-random `HKS` and no time bucket in `ckx`; [TAP run 45410737525](https://github.com/miSultanato/k15/actions/runs/45410737525) accepts a first ACK delayed 65s on all three pinned images | If impact merits it, test replay of an ACK after a synthetic connection is torn down; current test is delayed first ACK, not post-teardown replay |
| 15 | IPv4 checksum / ARP length and field checks | Short-ARP stale-buffer leak fixed in tested upstream image; IPv4 checksum and malformed ARP fields remain accepted | TAP differential: 24-byte ARP request elicited a reply containing a synthetic marker from the previous RX buffer on bounty; no marker reply on either `a2d8893` or current main. Invalid IPv4 checksum SYN and malformed ARP hrd/pro/hlen/plen still receive replies on all three | Keep IPv4 checksum and non-short ARP field acceptance classified as protocol-validation issues; assess short-frame leak's same-link impact separately |
| 16 | ECDSA nonce not reduced/rejected modulo n | No fix recorded in cited notes | Frozen assembly signer: n+1 produces the same valid signature as 1; n-1 verifies; n (zero residue) does not verify. Existing self-test also covers 2^256-1 and 2^256-2 | Characterize the distribution impact of raw 256-bit RDRAND values; this boundary test does not establish practical key recovery |
| 17 | apcount alignment | Fixed in `a2d8893` and current main | [Emitted-image run 45411656961](https://github.com/miSultanato/k15/actions/runs/45411656961) confirms `(apcount - tramp) mod 4 = 3` in bounty and `0` in both upstream images | Only AP startup/runtime validation remains optional; emitted-image alignment is asserted |
| 18 | GDT Accessed bits | Fixed in `a2d8893` and current main | [Emitted-image run 45411656961](https://github.com/miSultanato/k15/actions/runs/45411656961) confirms frozen descriptor access bytes `0x9A/0x92` vs upstream `0x9B/0x93` | No remaining binary-byte gap; runtime descriptor mutation is not tested |
| 19 | E820 SMAP signature unchecked | Fixed in `a2d8893` and current main | [Emitted-image run 45412245837](https://github.com/miSultanato/k15/actions/runs/45412245837) confirms the `cmp eax, 0x534D4150` instruction bytes are absent in frozen `boot.bin` and present in both upstream boot sectors | Add a synthetic BIOS return test for a wrong EAX signature and verify no memory-map entry is accepted; current evidence checks emitted instruction bytes only |
| 20 | NAME environment variable collision | Fixed in `a2d8893` and current main | [Source differential run 45408396045](https://github.com/miSultanato/k15/actions/runs/45408396045) confirms the environment-origin plus hostname guard is absent in bounty and present upstream; [Make-level collision test 45408609885](https://github.com/miSultanato/k15/actions/runs/45408609885) confirms bounty writes the runner hostname into `names.conf`; [build/certificate test 45412001815](https://github.com/miSultanato/k15/actions/runs/45412001815) confirms it becomes a `DNS:` SAN in the frozen cert but not in either upstream cert | No remaining build-time gap; the SAN regression is covered on all three pinned revisions |

## Important interpretation

- Owner status refers to upstream branch notes, not our frozen bounty image.
- The independent audit explicitly says no packet path was found to disclose the
  private key, connection key schedule, or another client's data. It also says
  its suggested fixes were sketches at the time of publication and not all had
  been assembled or run through project suites.
- Our QEMU framing differential confirms a parser discrepancy on the frozen
  image and rejection by the fixed revision for the tested malformed inputs.
  It does not establish a completed TLS handshake or application-data exchange.
- Our nonce samples establish only that no repeats were observed in those
  finite samples. They do not test the ECDSA range condition in finding 16.
- Our raw-frame fuzz corpus is not a substitute for deterministic protocol
  assertions for findings 2, 13 and 15.
- The source audit of the VM private scalar and byte-for-byte reconstruction of
  generated `ec.inc` are separate from this 20-item protocol/conformance list.

## Next bounded work, ordered

1. Add assembled-image/listing assertions for findings 17 and 18: actual
   `apcount` alignment and emitted GDT descriptor Accessed bits. The current
   successful check is source-level only.
2. Add a synthetic BIOS E820 response with a wrong SMAP signature for finding
   19, if the boot harness can inject it without modifying the frozen target.
3. Extend ACK and MSS tests to boundary values and 32-bit wraparound; current
   TAP coverage is one deliberately out-of-window ACK and MSS=100.
4. Complete the post-HelloRetryRequest second-ClientHello and CCS differential
   for finding 8.
5. Extend the authenticated TLSInnerPlaintext differential to more padding
   lengths and confirm exact fatal-alert/connection teardown semantics.
6. For finding 20, extend the Make-level `NAME=$(hostname)` regression to an
   ephemeral generated certificate and assert the resulting SAN.
7. Reproduce the short-site W^X result with an emitted-image page-table/NX
   assertion, in addition to the successful runtime `RET` probe.
8. Test stale SYN-cookie ACK replay after connection teardown and controlled
   delay for finding 14. The current cookie review is source-level only.

The TLS Finished/AEAD behavior (findings 9–10), HTTP Host/method behavior
(finding 12 and part of 4), ECDSA nonce boundaries (16), short-site W^X (1),
and authenticated TLSInnerPlaintext handling (11) already have local
differential evidence. The malformed-ClientHello transcript experiment still
requires a client that hashes exactly the bytes the server processes.

## Safety and branch discipline

All tests must run against locally built images or deterministic unit tests.
Do not send probes to the production host, run load/DoS tests, or attempt to
read production memory. Keep `bounty` pinned at the frozen commit and do not
merge upstream changes into it.
