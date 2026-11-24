# Short-ARP stale-buffer disclosure: bounded impact analysis

Date: 2026-11-24

Target: frozen `FileSherlock/k15` bounty image
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Reproduction already obtained

The local TAP differential in run
[45443936657](https://github.com/miSultanato/k15/actions/runs/45443936657)
primed a receive buffer with a synthetic marker frame, sent a 24-byte ARP
request, and observed the marker in the reply. That run used a non-IP
Ethernet frame as the primer; it demonstrated stale-buffer reuse, not a
natural victim packet.

- Frozen bounty: the reply contains the synthetic stale-buffer marker.
- First upstream fix and current upstream main: no marker reply is observed.

The test is local, synthetic, and uses a single-processor guest. It does not
read or probe production memory.

## Exact source behavior

In the frozen `src/os.asm` ARP branch:

1. The code checks the EtherType, ARP opcode, and a dword at frame offset 38.
2. It does not first compare the received frame length (`RXLEN`) with the
   42 bytes required for a complete Ethernet/ARP request.
3. It copies ten bytes beginning at frame offset 22 into the ARP reply.
4. A 24-byte input supplies only offsets 0..23. The copy therefore takes
   offsets 24..31 from whatever remained in that processor's receive buffer.
5. The dword check at offset 38 also reads beyond the current frame. A
   preceding full ARP request for the server naturally leaves the server IP
   at offsets 38..41, satisfying that check.

The first upstream fix adds a length gate before reading ARP fields:

```nasm
cmp dword [rbx+RXLEN], 42
jb .ret
```

That guard is present in both the first fix and current upstream main
(`src/tcp.asm`).

## What can be disclosed

For a preceding full Ethernet/ARP request, frame offsets 22..31 are:

- offsets 22..27: sender hardware address (MAC);
- offsets 28..31: sender protocol address (IPv4 address).

The short request itself contributes offsets 22..23. The remaining eight
bytes copied into the reply (offsets 24..31) are stale: the last four bytes
of the preceding sender MAC plus its complete sender IPv4 address.

This is a narrow metadata disclosure, not a packet-payload disclosure. The
synthetic test marker demonstrates the byte path; it does not prove that a
victim's packet was disclosed in a live network. A preceding ARP request
addressed to the server provides a plausible natural buffer state, because
its target protocol address at offsets 38..41 is the server's address.

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
  ARP request for the server is one plausible example.
- The test uses `SMP=1`; it does not establish queue/processor selection
  behavior or disclosure reliability on a multi-processor production host.
- The demonstrated leak is eight stale bytes. It is not a private-key,
  TLS traffic-key, or arbitrary-memory disclosure, and it is not evidence
  of Internet reachability.

## Assessment

Classify this as a **same-link stale receive-buffer metadata disclosure** in
the frozen bounty image. It is stronger than a mere malformed-ARP
conformance issue, but materially narrower than arbitrary memory disclosure
or remote code execution.

The one-instruction upstream length guard prevents both the stale dword
read and the stale reply copy for frames shorter than 42 bytes. The
three-way synthetic differential confirms the guard's observed effect.

## Safe follow-up

The follow-up is implemented in `test_arp_short_frame.py`: it primes the
single-queue RX ring with 32,768 valid synthetic ARP requests, drains every
ordinary marker-bearing reply, then sends 24-byte short requests and checks
for the stale suffix. The workflow uses `SMP=1 MEM=256`; the test splits the
priming into 512 batches of 64 to avoid TAP burst loss.

Three-way run 45463654039 confirmed the marker on the frozen bounty and no
marker on the first upstream fix. The current-upstream leg of that run failed
during priming (303/512 replies in the old 512-frame burst), so it is a
harness packet-loss result, not a target finding. The paced 64-frame-batch
rerun is tracked in run 45464009546 and remains pending at the time of this
update. Keep all traffic on the local guest, use synthetic MAC/IP values, and
upload no packet captures or artifacts.
