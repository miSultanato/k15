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
| 1 | Site bytes may share executable page (W^X) | Fixed in the tested upstream revisions | [Three-way emitted-layout + QEMU run 45439460997](https://github.com/miSultanato/k15/actions/runs/45439460997): frozen final site byte is executable (`site_page=0x103 < CODEPG=0x104`) and guest stays alive; both upstream images map it NX (`site_page=0x104 = CODEPG=0x104`) and reset before serving | Emitted-layout calculation and runtime synthetic-RET differential now agree. This reconstructs the page threshold from image layout/source; it does not read live guest PTE memory |
| 2 | TCP data accepted without acceptable ACK | Fixed in both `a2d8893` and current upstream main | [assertive three-way TAP run 45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924) plus [forced-wrap matrix](https://github.com/miSultanato/k15/actions/runs/45413051340): after a valid handshake, ACK offsets +1, +63, +64, +65535 and +65536 beyond SND.NXT all get HTTP responses on bounty; both upstream images produce no HTTP response. With SND.NXT forced to `0xFFFFFFC2`, +65536 wraps to `0x0000FFC2` and is still accepted only by bounty | The test now fails if bounty stops reproducing or either fixed image accepts an out-of-window ACK |
| 3 | Session ID >32 and length wrap | Fixed in both `a2d8893` and current upstream main | [Three-way framing/HRR run 45436733972](https://github.com/miSultanato/k15/actions/runs/45436733972): correctly encoded 33-byte and 255-byte `legacy_session_id` values both receive ServerHello on frozen bounty; both upstream images return fatal alerts (33 bytes: `decode_error`) | Both oversized lengths are now covered with a correctly sized wire vector. The earlier apparent frozen 255-byte rejection was a test-vector construction bug and has been withdrawn |
| 4 | Lowercase HTTP method may hang | Fixed in tested upstream `a2d8893` and current main | TLS 1.3 differential: lowercase `get` gets no HTTP response on bounty; both upstream images return 405. Unknown `FOO` returns 405 on all three | Keep the lowercase-method regression and test other case variants |
| 5 | ServerHello echoes legacy_version | Fixed in both `a2d8893` and current upstream main | QEMU differential: ClientHello legacy_version 0x0301 is echoed as 0x0301 by bounty; both upstream images send ServerHello legacy_version 0x0303 | Add more malformed legacy_version values and assert 0x0303 or fatal alert |
| 6 | Handshake type/declared length unchecked | Fixed in both `a2d8893` and current upstream main | Frozen image treats a type-2 message as ClientHello and emits ServerHello. Transcript-faithful inner-short and outer-short clients both verify server CertificateVerify/Finished and receive HTTP 200 on bounty; both upstream images reject both with fatal `decode_error` (alert 50) in [run 45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415) | One-byte truncations are now covered end-to-end. Broader truncation offsets and ordinary-client interoperability remain separate questions; no key disclosure shown |
| 7 | legacy_compression_methods unchecked | Fixed in both `a2d8893` and current upstream main | QEMU differential: non-null compression method gets ServerHello on bounty; both upstream images send fatal alert 47 (`illegal_parameter`) | Add compression vector length/value matrix and require fatal alert |
| 8 | Dummy ChangeCipherSpec absent with non-empty session ID | Present in both `a2d8893` and current upstream main | [OpenSSL wire-capture run 45436733972](https://github.com/miSultanato/k15/actions/runs/45436733972): forced HRR completes with exactly two ClientHellos and two ServerHellos on all three images. Frozen bounty sends 0 server CCS records; both upstream images send 1. Normal-path CCS is independently confirmed by [run 45417214217](https://github.com/miSultanato/k15/actions/runs/45417214217) | HRR second-ClientHello and CCS behavior are now covered end-to-end on all three pinned revisions |
| 9 | Client Finished not verified | Not listed as fixed in cited notes | Existing local differential: corrupt client Finished, then send valid app data; bounty, `a2d8893` and current main all return HTTP. New omission control discards Finished entirely and sends only application data; workflow result pending | Static path shows the server accepts application records under the client application key without verifying Finished. This is not proof an attacker without the shared secret can forge application data; await omission-control runtime evidence |
| 10 | Bad AEAD tag does not terminate connection | Not listed as fixed in cited notes | Local end-to-end differential: corrupt AEAD tag, then replay the original valid same-sequence record; all three images process the valid record | Determine protocol/security impact; no traffic-key forgery is demonstrated |
| 11 | Inner plaintext with no content type accepted | Fixed in `a2d8893` and current main | [Expanded three-way QEMU test 45414676678](https://github.com/miSultanato/k15/actions/runs/45414676678): authenticated all-zero inner plaintext lengths 1, 2, 16, 255 and 300 are followed by a valid request; frozen bounty processes it for all lengths, while both upstream revisions close without processing it | Additional padding lengths are covered; a deeper wire-level assertion of the exact fatal-alert description is optional. Synthetic local keylog material only |
| 12 | Missing Host / absolute-form HTTP handling | Reported as not security-relevant by owner in earlier note; no fix recorded | Not tested in current bounded suite | Treat as HTTP conformance only; decide whether worth byte budget |
| 13 | TCP segment may exceed peer MSS below 216 | Fixed in both `a2d8893` and current upstream main | [assertive three-way TAP run 45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924): bounty accepts MSS 0, 1, 100, 179, 180, 181, 215 and 216 and sends 180-byte payloads; fixed/current send no SYN-ACK for 0..215 and accept 216. The frozen payload exceeds the peer MSS whenever it is below 180 | No remaining MSS-boundary gap in this matrix; upstream may reject small MSS or accept it only while respecting the negotiated size |
| 14 | ISN/cookies lack clock component | No fix recorded in cited notes | [Three-way 65s post-teardown replay run 45443936657](https://github.com/miSultanato/k15/actions/runs/45443936657): after a complete FIN/FIN close and 65-second wait, replaying the original SYN-cookie ACK and sending a different-length request produces a response whose ACK equals the new request end sequence on all three images. The first ACK was also independently accepted after 65s in [run 45410737525](https://github.com/miSultanato/k15/actions/runs/45410737525) | Replay after teardown is confirmed for at least 65 seconds on all three tested revisions. This is common behavior, not a bounty-only regression; impact and threat model remain separate questions |
| 15 | IPv4 checksum / ARP length and field checks | Cross-sender unicast short-ARP stale-buffer disclosure fixed in tested upstream images; IPv4 checksum and malformed full-length ARP fields remain accepted | Three-way TAP run 45466831548: 2,048 valid unicast ARP requests from a synthetic victim, then a 24-byte request from a distinct sender. Frozen bounty reply contains victim MAC suffix/IP; first fix and current main reject it. Invalid IPv4 checksum SYN and malformed ARP hrd/pro/hlen/plen still receive replies on all three | Keep the eight-byte same-link metadata disclosure separate from protocol-validation issues; do not describe it as key or arbitrary-memory disclosure |
| 16 | ECDSA nonce not reduced/rejected modulo n | No fix recorded in cited notes | Frozen assembly signer: n+1 produces the same valid signature as 1; n-1 verifies; n (zero residue) does not verify. Existing self-test also covers 2^256-1 and 2^256-2 | Characterize the distribution impact of raw 256-bit RDRAND values; this boundary test does not establish practical key recovery |
| 17 | apcount alignment | Fixed in `a2d8893` and current main | [Emitted-image run 45411656961](https://github.com/miSultanato/k15/actions/runs/45411656961) confirms `(apcount - tramp) mod 4 = 3` in bounty and `0` in both upstream images | Only AP startup/runtime validation remains optional; emitted-image alignment is asserted |
| 18 | GDT Accessed bits | Fixed in `a2d8893` and current main | [Emitted-image run 45411656961](https://github.com/miSultanato/k15/actions/runs/45411656961) confirms frozen descriptor access bytes `0x9A/0x92` vs upstream `0x9B/0x93` | No remaining binary-byte gap; runtime descriptor mutation is not tested |
| 19 | E820 SMAP signature unchecked | Fixed in `a2d8893` and current main | [Boot hardening run 45437038597](https://github.com/miSultanato/k15/actions/runs/45437038597) executes the unchanged 16-bit E820 loop under Unicorn: all three revisions accept a valid SMAP response; frozen bounty counts a successful INT 15h response with wrong EAX as an entry, while both upstream images reject it | The boot-code path is now covered with a synthetic BIOS response. This remains deterministic emulation, not validation against physical BIOS implementations |
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
- Deterministic protocol assertions now cover findings 2, 13 and 15 through
  the ACK/MSS and cross-sender ARP TAP regressions. The raw-frame fuzz corpus
  remains supplementary rather than a substitute for those assertions.
- The source audit of the VM private scalar and byte-for-byte reconstruction of
  generated `ec.inc` are separate from this 20-item protocol/conformance list.

## Next bounded work, ordered

1. If stronger W^X evidence is needed, add a QEMU live page-table read for the
   short-site mapping. The emitted-image CODEPG calculation and synthetic-RET
   runtime differential already agree; neither reads the live PTE directly.
2. The cross-sender unicast ARP regression is complete in run
   45466831548. Both upstream variants reject the stale suffix and the
   frozen bounty reproduces it. Keep the impact limited to eight metadata
   bytes and single-processor local-buffer conditions.
3. Expand the one-byte inner/outer ClientHello truncation vectors only if
   additional offsets materially clarify the parser boundary. Both current
   vectors already complete TLS 1.3 on bounty and are rejected upstream.
4. Consider multi-processor queue selection only if it can be tested safely
   and deterministically. The current unicast reproduction uses SMP=1 and
   does not establish production multi-queue reliability or Internet reachability.

The 65-second post-FIN/FIN SYN-cookie ACK replay is already confirmed on all
three revisions in run 45443936657; it is common behavior, not a bounty-only
regression. The transcript-faithful ClientHello experiment is also complete
in run 45460246415. Neither remains an outstanding reproduction task.

The emitted-image checks for AP counter alignment and GDT Accessed bits
(findings 17–18), E820 SMAP instruction presence and synthetic BIOS response
(19), and the generated certificate SAN regression (20) now pass. The TCP ACK-window matrix (2),
peer-MSS boundary tests (13), short-site W^X (1), authenticated
TLSInnerPlaintext (11), TLS Finished/AEAD (9–10), HTTP Host/method behavior
(4, 12), and ECDSA nonce boundaries (16) have local differential evidence.
The malformed-ClientHello transcript experiment is complete: the custom
Python client hashes the exact bytes processed by the server, verifies
CertificateVerify and Finished, and sends an encrypted HTTP request.

## Safety and branch discipline

All tests must run against locally built images or deterministic unit tests.
Do not send probes to the production host, run load/DoS tests, or attempt to
read production memory. Keep `bounty` pinned at the frozen commit and do not
merge upstream changes into it.
