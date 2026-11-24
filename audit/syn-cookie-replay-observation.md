# SYN-cookie ACK replay after orderly connection close

Date: 2026-11-24

## Result

The deterministic three-way TAP probe observed that the exact ACK which
completes a SYN-cookie handshake can be replayed after the resulting TCP
connection has completed an orderly FIN/FIN close. After a further 65-second
delay, the frozen bounty image, the pinned first upstream fix, and pinned
current upstream main all accepted the replayed ACK and processed a new HTTP
request sent at the original client sequence number.

The probe compares the server's ACK after the replay with the end sequence of
the new request. The observed values match, so this is not merely a SYN-ACK or
an empty response: the replayed cookie recreates connection state and the
different-length HTTP request is processed.

Evidence:
- Earlier three-way run: https://github.com/miSultanato/k15/actions/runs/45443936657
- Expanded IPv4/ARP/TCP run: https://github.com/miSultanato/k15/actions/runs/45468109924

The expanded run completed successfully on all three images. In the fixed and
current upstream images, the ARP stale-buffer probe rejects the disclosure
while the cookie replay observation remains the same.

## Source explanation

In the pinned upstream revisions, `src/conn.asm` contains the keyed hash
(`prf`) and cookie verifier (`ckx`). Both revisions have the same
`conn.asm` blob SHA, `d4929469a0faf0394d76432f4eecfdbe808db395`.

The source comments describe the SYN-ACK sequence number as a cookie derived
from:
- the client's initial sequence number;
- a keyed hash of the client's address and ports, using random boot-time
  AES round keys;
- the negotiated window-scale and MSS table values.

The verifier recomputes the expected cookie from the arriving packet's
sequence number, tuple and ACK. The cookie contains no visible time bucket or
single-use counter. In `tcp.asm`, a valid first ACK with no extant connection
takes the `.miss -> .make` path and materializes a connection slot. A completed
FIN close frees the old slot, so replaying the same valid cookie ACK can create
a new slot.

The boot-time secret means the cookie is not transferable to a different
address/port tuple and should change after a reboot/key regeneration. The
expanded test now replays the same ACK under a different source port before
the 65-second same-tuple replay; all three images reject the changed-port
attempt and accept the original tuple. This is direct evidence of tuple
binding in the tested IPv4 path. The observed 65-second replay shows that the
cookie remains valid beyond the short SYN retransmission-cache interval; it
does not establish validity across reboots or key rotation.

## Interpretation

**Classification: reproducible stateless-cookie replay property; security
impact not yet established.**

This is distinct from the confirmed stale-buffer ARP disclosure and the
frozen-only ACK-window acceptance defect:

- It reproduces on the frozen bounty and both upstream revisions.
- It does not distinguish the vulnerable frozen image from the fixed/current
  images in this test.
- It requires the original cookie ACK (or equivalent knowledge of the
  authenticated tuple, client sequence and cookie); the same ACK under a
  different source port is rejected by all three tested images.
- The test uses a synthetic client and raw packets on an isolated TAP network.
  It does not demonstrate an off-path attacker forging a cookie, crossing
  address/port tuples, bypassing application authentication, or reaching a
  production service.
- It does not show that the server's boot-time key or any TLS private key is
  disclosed.

A captured, replayable handshake ACK can apparently recreate a TCP connection
after orderly close, but whether this is an exploitable weakness depends on
the intended SYN-cookie threat model and the ability of an attacker to obtain
and replay the packet with the same four-tuple. Treat it as a protocol
observation requiring threat-model review, not as a bounty-grade vulnerability
claim at this stage.

## Test accuracy correction

The probe closes the first connection with a normal FIN/FIN exchange. It does
not use an RST fallback in the observed runs. The previous log label
"cookie ACK replay after RST teardown" was inaccurate and has been corrected
to "FIN teardown". The test intentionally reports the replay result rather
than failing on it, because all three revisions currently exhibit the same
behavior.

## Safe next steps

1. Keep this observation separate from the bounty-specific findings.
2. Review whether the documented SYN-cookie design intends to prevent replay
   after connection teardown or only to avoid allocating state before a
   valid ACK arrives.
3. If the threat model requires replay freshness, discuss a bounded time
   component or another anti-replay mechanism with the upstream maintainer;
   do not patch the frozen bounty image.
4. Any further validation stays local, synthetic and isolated. Do not send
   probes to the production service.
