# IPv4 checksum and full-length ARP validation observations

Date: 2026-11-24

## Differential result

The deterministic TAP matrix in
`audit/test_ip_arp_validation.py` sends only synthetic frames to the local
QEMU guest. It observes the following on the frozen bounty, first upstream
fix and current upstream main:

- A SYN with a valid IPv4 header checksum receives a SYN-ACK.
- A SYN with an intentionally invalid IPv4 header checksum also receives a
  SYN-ACK. Its TCP checksum is independently computed and remains valid.
- Full-length ARP requests with hardware type 2, protocol type IPv6, hardware
  length 1, or protocol length 1 receive ARP replies.
- The guest remains healthy and a normal TLS request succeeds after these
  probes.

The three-way run is
https://github.com/miSultanato/k15/actions/runs/45468109924.

These are observed input-validation choices shared by all three revisions;
they are not differential bounty-only findings.

## IPv4 source path

In pinned current upstream `src/tcp.asm`, the IPv4 receive path checks:

1. EtherType is IPv4.
2. Version and header length are exactly `0x45` (IPv4, 20-byte header).
3. Fragment/flags bits covered by `0xFF3F` are clear.
4. Protocol is TCP (or the separately handled DHCP path).
5. Destination address belongs to the server.
6. Total length is at least the minimum IPv4+TCP header and does not exceed
   the received Ethernet frame.
7. The TCP checksum over the pseudo-header and TCP segment is valid.

The source comment at the version/IHL check explicitly notes that the IPv4
header has its own checksum, but the fields used are fixed or covered by the
TCP checksum. The implementation does not calculate or verify the IPv4 header
checksum itself. The probe deliberately preserves a valid TCP checksum while
flipping one bit in the IPv4 header checksum, which explains why the SYN is
still processed.

This is a protocol-conformance/robustness observation. The probe does not show
that changing the unchecked TTL, DSCP or identification fields causes a
security boundary to be crossed. It should not be described as an exploit
without a separate demonstrated consequence.

## ARP source path

The ARP branch in `src/tcp.asm` checks EtherType, the 42-byte minimum frame
length added by the upstream fix, request opcode, and whether the target
protocol address belongs to the server. It does not validate all ARP
hardware/protocol metadata fields (hardware type, protocol type, hardware
length and protocol length) before constructing a reply.

The full-length malformed-field probes therefore still receive replies on
both upstream revisions. This is separate from the short-frame disclosure:

- **Short frame:** the frozen image can copy stale receive-buffer bytes; the
  upstream minimum-length gate prevents the stale read/reply.
- **Malformed full-length ARP:** the request is long enough to avoid the
  stale-buffer condition, but its ARP metadata is not fully validated. No
  stale bytes or other security consequence were observed.

## Assessment

Keep these as low-priority protocol-validation observations, not as confirmed
security vulnerabilities. The high-confidence ARP finding remains the
cross-sender, eight-byte stale receive-buffer disclosure in the frozen image.
The upstream fix's relevant security effect is the early length gate; it does
not attempt to make the entire ARP parser a strict RFC conformance validator.

All testing remains synthetic, local and isolated. No probes are sent to
15kb.org.


## Upstream audit cross-reference

The upstream maintainer's
[issue #1, finding 15](https://github.com/FileSherlock/k15/issues/1)
already records the missing IPv4 header checksum verification and incomplete
ARP metadata validation. It notes that the IPv4 fields protected only by that
checksum (TOS, ID and TTL) are not used by the server, so the observed effect
is nil; adding a 20-byte checksum calculation is a size/conformance trade-off.
For ARP, the maintainer fixed the short-frame condition on the upstream
revision tested here, while the full-length hardware/protocol metadata checks
remain absent. Our TAP matrix confirms that distinction.
