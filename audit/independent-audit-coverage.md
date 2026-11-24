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
| 1 | Site bytes may share executable page (W^X) | Fixed on main, per owner follow-up | No dedicated first-byte-of-short-site regression in our current bounded suite | Reproduce original short-site layout and verify NX on first site page |
| 2 | TCP data accepted without acceptable ACK | Fixed in tested upstream `a2d8893` image | TAP differential: after a valid handshake, an HTTP request with ACK 0x10000 beyond SND.NXT gets an HTTP response on bounty; fixed image produces no HTTP response | Expand ACK matrix across below/equal/inside/above window and 32-bit wraparound |
| 3 | Session ID >32 and length wrap | Fixed in tested upstream `a2d8893` image | TAP/QEMU differential: 33-byte legacy_session_id gets ServerHello on bounty; fixed image sends fatal `decode_error` | Add sid=255 and length-wrap boundary cases |
| 4 | Lowercase/unknown HTTP method may hang | Owner reports fixed on main | TAP probe sent `get` and `FOO` with valid HTTP/1.1 framing; both bounty and `a2d8893` returned HTTP 200, so the reported hang was not reproduced | Expand to other methods, malformed request lines, missing Host and repeated requests before treating as resolved |
| 5 | ServerHello echoes legacy_version | Fixed in tested upstream `a2d8893` image | QEMU differential: ClientHello legacy_version 0x0301 is echoed as 0x0301 by bounty; fixed image sends ServerHello legacy_version 0x0303 | Add more malformed legacy_version values and assert 0x0303 or fatal alert |
| 6 | Handshake type/declared length unchecked | Fixed in tested upstream `a2d8893` image | Frozen image treats a type-2 handshake message as ClientHello and emits ServerHello; fixed image returns fatal `unexpected_message` (alert 10). Length mismatches are also rejected | Retain exact type/length cases and assert fatal alert class/description |
| 7 | legacy_compression_methods unchecked | Fixed in tested upstream `a2d8893` image | QEMU differential: non-null compression method gets ServerHello on bounty; fixed image sends fatal alert 47 (`illegal_parameter`) | Add compression vector length/value matrix and require fatal alert |
| 8 | Dummy ChangeCipherSpec absent with non-empty session ID | Present in upstream framing-fix commit | QEMU differential: 32-byte legacy_session_id; bounty's record after ServerHello is type 23, fixed upstream's is type 20 | Add HelloRetryRequest-path coverage and test additional non-empty session_id lengths |
| 9 | Client Finished not verified | Not listed as fixed in cited notes | Source comment says client Finished uses other keys and is ignored; post-ClientHello records go to application-key `record()` | Local end-to-end test: corrupt client Finished, then send valid app data; record actual server behavior |
| 10 | Bad AEAD tag does not terminate connection | Not listed as fixed in cited notes | Source tag mismatch branches to `.no`, which returns without fatal alert/close; not dynamically tested | Corrupt an authenticated record tag, then send a valid app record; assert close/alert vs continued processing |
| 11 | Inner plaintext with no content type accepted | Fixed on main | Not independently recorded in current test inventory | Send authenticated TLSInnerPlaintext containing only zero padding; require rejection |
| 12 | Missing Host / absolute-form HTTP handling | Reported as not security-relevant by owner in earlier note; no fix recorded | Not tested in current bounded suite | Treat as HTTP conformance only; decide whether worth byte budget |
| 13 | TCP segment may exceed peer MSS below 216 | Fixed in tested upstream `a2d8893` image | TAP differential: peer MSS=100; bounty advertises MSS=1460 and sends a 180-byte data segment; fixed image sends no SYN-ACK | Extend boundary matrix to MSS values 0..215 and confirm refusal/segment limits |
| 14 | ISN/cookies lack clock component | No fix recorded in cited notes | Not tested | Offline deterministic cookie tests across time buckets; assess replay window |
| 15 | IPv4 checksum / ARP length and field checks | Short-ARP stale-buffer leak fixed in tested upstream image; IPv4 checksum and malformed ARP fields remain accepted | TAP differential: 24-byte ARP request elicited a reply containing a synthetic marker from the previous RX buffer on bounty; no marker reply on `a2d8893`. Invalid IPv4 checksum SYN and malformed ARP hrd/pro/hlen/plen still receive replies on both | Keep IPv4 checksum and non-short ARP field acceptance classified as protocol-validation issues; assess short-frame leak's same-link impact separately |
| 16 | ECDSA nonce not reduced/rejected modulo n | No fix recorded in cited notes | Frozen assembly signer: n+1 produces the same valid signature as 1; n-1 verifies; n (zero residue) does not verify. Existing self-test also covers 2^256-1 and 2^256-2 | Characterize the distribution impact of raw 256-bit RDRAND values; this boundary test does not establish practical key recovery |
| 17 | apcount alignment | Fixed on main | No dedicated binary-symbol alignment assertion | Assert symbol offset mod 4 = 0 in built image |
| 18 | GDT Accessed bits | Fixed on main | Boot tests passed, but no explicit GDT byte assertion | Assert descriptor access bytes include Accessed bit |
| 19 | E820 SMAP signature unchecked | Fixed on main | Normal QEMU boot does not test malformed BIOS return | Unit/synthetic boot-path test for wrong signature |
| 20 | NAME environment variable collision | Fixed on main | Build passed in GitHub runner; no controlled NAME collision test | Build with NAME equal to hostname and assert expected certificate SAN |

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

1. Reproduce findings 9 and 10 against the fixed upstream image for a clean
   differential baseline; keep the results separate from key disclosure.
2. Add exact boundary tests for findings 2, 13 and 15 (ACK, MSS, ARP, IPv4).
3. Characterize finding 8 (dummy ChangeCipherSpec) with the same instrumented
   local TLS client.
4. Add low-cost binary assertions for findings 17 and 18.
5. Only then revisit other gaps. The malformed-ClientHello transcript test
   still requires a client that hashes exactly the bytes the server processes.

## Safety and branch discipline

All tests must run against locally built images or deterministic unit tests.
Do not send probes to the production host, run load/DoS tests, or attempt to
read production memory. Keep `bounty` pinned at the frozen commit and do not
merge upstream changes into it.
