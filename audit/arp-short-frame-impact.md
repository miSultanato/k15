# Short-ARP stale receive-buffer disclosure: bounded impact analysis

Date: 2026-11-24

Target: frozen FileSherlock/k15 bounty image
ab93479ebc7c85274c722b16897148286d1cfca3.

## Differential reproduction

The three-way local TAP run
https://github.com/miSultanato/k15/actions/runs/45466831548
completed successfully against the frozen bounty, first upstream fix and
current upstream main.

The test uses two distinct synthetic identities and a unicast primer:

1. It sends a normal broadcast ARP probe to discover the guest MAC.
2. A synthetic victim sends 2,048 complete unicast ARP requests to that MAC.
   Each request has a distinct victim MAC/IP and receives a normal reply.
3. A different synthetic sender sends a 24-byte ARP request to the guest.
   It contains only the first two bytes of the sender hardware address.
4. The test checks that the reply is Ethernet-addressed to the short-frame
   sender but contains the victim's stale MAC suffix and IPv4 address in its
   ARP target fields.

Observed:

- Frozen bounty: the reply exposes the prior unicast victim MAC/IP suffix.
- First upstream fix: no prior-victim marker; the regression test passes in
  reject mode.
- Current upstream main: no prior-victim marker; the regression test passes
  in reject mode.

The workflow now fails if either fixed image emits the marker. The test runs
inside an isolated network namespace with synthetic identities and a local
QEMU guest. The packet socket uses temporary promiscuous membership only to
count the victim's unicast replies; the membership disappears when the socket
closes. No packet captures or VM images are uploaded.

## Exact source behavior

In the frozen src/os.asm ARP branch:

1. The code checks the EtherType, ARP opcode, and a dword at frame offset 38.
2. It does not first compare the received frame length (RXLEN) with the
   42 bytes required for a complete Ethernet/ARP request.
3. It copies ten bytes beginning at frame offset 22 into the ARP reply.
4. A 24-byte input supplies only offsets 0..23. The copy therefore takes
   offsets 24..31 from whatever remained in that processor's receive buffer.
5. The dword check at offset 38 also reads beyond the current frame. A
   preceding full ARP request for the server naturally leaves the server IP
   at offsets 38..41, satisfying that check.

The first upstream fix adds a length gate before reading ARP fields:

    cmp dword [rbx+RXLEN], 42
    jb .ret

That guard is present in both the first fix and current upstream main
(src/tcp.asm).

## What is disclosed

For a preceding full Ethernet/ARP request, frame offsets 22..31 are:

- offsets 22..27: sender hardware address (MAC);
- offsets 28..31: sender protocol address (IPv4 address).

The short request itself contributes offsets 22..23. The remaining eight
bytes copied into the reply (offsets 24..31) are stale: the last four bytes
of the preceding sender MAC plus its complete sender IPv4 address.

The unicast test is stronger than the earlier broadcast primer: the victim's
request is addressed directly to the guest MAC, and the resulting reply to
the short-frame sender carries the victim's stale suffix. Unicast ARP probes
are a real neighbor-reachability mechanism when a previous hardware mapping
is known but stale; Linux documents this through ucast_solicit:
https://man7.org/linux/man-pages/man7/arp.7.html

This is a narrow same-link metadata disclosure, not a packet-payload
disclosure. The MAC/IP values are synthetic and the test does not establish
that a production victim's traffic was exposed. It demonstrates that a
unicast request from one peer can leave bytes that a different peer causes
the frozen image to copy into its reply.

For a preceding IPv4/TCP frame, the same offsets have different meanings.
In particular, offsets 38..41 are part of the TCP sequence number, so the
ARP-branch dword check will not generally pass unless those bytes happen to
equal the server IPv4 address. Do not generalize the ARP-request case to
every preceding Ethernet frame.

## Preconditions and limits

- The short frame must be processed by the same processor-local receive
  buffer that still contains the preceding frame.
- The attacker must be able to inject Ethernet/ARP traffic on the same
  Layer-2 segment.
- The prior buffer contents must satisfy the offset-38 dword check; a full
  unicast ARP request for the server is one demonstrated example.
- The test uses SMP=1 MEM=256; it does not establish queue/processor
  selection behavior or disclosure reliability on a multi-processor
  production host.
- The demonstrated disclosure is eight stale metadata bytes. It is not a
  private-key, TLS traffic-key, arbitrary-memory, or Internet-reachable
  disclosure.

## Assessment

Classify this as a same-link stale receive-buffer metadata disclosure in
the frozen bounty image. It is stronger than a malformed-ARP conformance
issue, but materially narrower than arbitrary memory disclosure or remote
code execution.

The early upstream length gate prevents both the stale dword read
and the stale reply copy for frames shorter than 42 bytes. The three-way
unicast differential confirms the guard's observed effect.

## Safe follow-up

The cross-sender unicast regression is implemented in
audit/test_arp_short_frame.py and enforced by the three-way TAP workflow.
Keep future tests local, synthetic and bounded. Do not attempt to access
production memory or send probes to 15kb.org.
