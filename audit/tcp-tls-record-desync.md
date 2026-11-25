# TCP ACK-window desynchronization of TLS application records

Date: 2026-11-25

## Reproduction

The isolated probe `test_tls_tcp_ack_desync.py` establishes a local TLS 1.3
connection using OpenSSL MemoryBIO and sends the client's Finished record
normally. It then creates a valid application-data record for an HTTP request,
flips one bit in the first 16 bytes (the record's authenticated ciphertext
prefix), and sends that prefix with a TCP ACK 65,536 beyond the server's
`SND.NXT`. Finally, it retransmits the complete original record at the
original TCP sequence number.

The three-way QEMU/TAP differential in
[run 45574294391](https://github.com/miSultanato/k15/actions/runs/45574294391)
produced:

| Image | First ACK after invalid-ACK prefix | HTTP response |
|---|---:|---|
| Frozen bounty | `0x5a6b8292` (prefix end) | No |
| First upstream fix | `0x5a6b8282` (original sequence) | Yes |
| Current upstream | `0x5a6b8282` (original sequence) | Yes |

The prefix is 16 bytes and the complete TLS application record is 76 bytes.
The frozen image advances its TCP receive sequence over the invalid-ACK
prefix. When the valid retransmission arrives at the original sequence, the
already-consumed prefix is treated as overlap and only the remaining suffix
is appended. The TLS layer consequently receives a corrupted record and
does not produce an HTTP response. Both upstream images reject the invalid
ACK payload, retain the original receive sequence, and accept the complete
authenticated record.

## Security interpretation

This is an end-to-end consequence of the TCP ACK-window defect: a party able
to inject a segment into an established connection with the right tuple and
sequence information can desynchronize the byte stream and cause a valid TLS
application record to be lost. The observed result is record-level
availability/integrity disruption (the request is not processed), not a TLS
authentication bypass.

The test deliberately corrupts the ciphertext prefix, and the frozen image
does not return HTTP after the corrupted record. It therefore provides
positive evidence that the AEAD authentication check still prevents this
particular malformed record from becoming an accepted request. It does not
show that an attacker can forge a valid AEAD tag, derive traffic keys, inject
authenticated application data, recover credentials, or attack off-path
without the connection tuple and sequence state.

All packets are synthetic and confined to isolated QEMU/TAP guests. No
production service is contacted. See also
`tcp-ack-injection-impact.md` for the underlying ACK-window state-machine
defect and its other sequence-aware tests.
