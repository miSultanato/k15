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
| 2 | TCP data accepted without acceptable ACK | No fix recorded in cited owner notes | Raw malformed-frame fuzz is not a proof of ACK-window enforcement | Add deterministic sequence/ACK matrix with exact expected ACK/drop behavior |
| 3 | Session ID >32 and length wrap | Fixed on main | Not separately asserted in our current differential framing matrix | Add sid=33 and sid=255 regression cases; require decode_error |
| 4 | Lowercase/unknown HTTP method may hang | Fixed on main | Existing race/TLS tests do not establish method semantics | Test lowercase get, unknown token, and known-but-disallowed method |
| 5 | ServerHello echoes legacy_version | Fixed on main | Not independently recorded in current test inventory | Assert ServerHello legacy_version is 0303 for malformed legacy_version inputs |
| 6 | Handshake type/declared length unchecked | Fixed on main | Our frozen-vs-fixed differential framing tests cover type/length acceptance and rejection | Retain exact regression cases and verify alert description |
| 7 | legacy_compression_methods unchecked | Fixed on main | Not independently recorded in current test inventory | Assert compression vector other than 01 00 gets illegal_parameter |
| 8 | Dummy ChangeCipherSpec absent with non-empty session ID | Not listed as fixed in cited notes | Not tested | Add compatibility regression for session_id lengths 1 and 32 |
| 9 | Client Finished not verified | Not listed as fixed in cited notes | Source comment says client Finished uses other keys and is ignored; post-ClientHello records go to application-key `record()` | Local end-to-end test: corrupt client Finished, then send valid app data; record actual server behavior |
| 10 | Bad AEAD tag does not terminate connection | Not listed as fixed in cited notes | Source tag mismatch branches to `.no`, which returns without fatal alert/close; not dynamically tested | Corrupt an authenticated record tag, then send a valid app record; assert close/alert vs continued processing |
| 11 | Inner plaintext with no content type accepted | Fixed on main | Not independently recorded in current test inventory | Send authenticated TLSInnerPlaintext containing only zero padding; require rejection |
| 12 | Missing Host / absolute-form HTTP handling | Reported as not security-relevant by owner in earlier note; no fix recorded | Not tested in current bounded suite | Treat as HTTP conformance only; decide whether worth byte budget |
| 13 | TCP segment may exceed peer MSS below 216 | Fixed on main | Raw frame fuzz is not a targeted MSS conformance test | SYN matrix with MSS 0..215 and assert reset/no oversized response |
| 14 | ISN/cookies lack clock component | No fix recorded in cited notes | Not tested | Offline deterministic cookie tests across time buckets; assess replay window |
| 15 | IPv4 checksum / ARP length and field checks | ARP short-frame issue fixed on main; IPv4 checksum status unclear | Raw frame fuzz is broad but does not prove each field check | Target ARP hlen/plen/hrd/pro values and IPv4 checksum independently |
| 16 | ECDSA nonce not reduced/rejected modulo n | No fix recorded in cited notes | `tools/ec.py` self-test signs and verifies with k=2^256-1 and 2^256-2 (P-256); nonce sampling does not report effective residues | Add explicit n-1, n, n+1 vectors and compare reference vs assembly/VM behavior |
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

1. Add deterministic regressions for findings 8, 9 and 10. Finding 9 is the
   most important TLS semantic gap to characterize, but it is not a key
   extraction primitive.
2. Add exact boundary tests for findings 2, 13 and 15.
3. Add arithmetic boundary tests for finding 16. Do not infer range safety
   from uniqueness sampling.
4. Add low-cost binary assertions for findings 17 and 18.
5. Only then revisit the full malformed-ClientHello transcript test. A
   purpose-built client must hash exactly the bytes the server processes;
   mutating an OpenSSL-generated ClientHello after serialization is invalid.

## Safety and branch discipline

All tests must run against locally built images or deterministic unit tests.
Do not send probes to the production host, run load/DoS tests, or attempt to
read production memory. Keep `bounty` pinned at the frozen commit and do not
merge upstream changes into it.
