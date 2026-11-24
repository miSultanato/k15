# Frozen-source review: TCP SYN cookie time component

Date: 2026-11-24

Target: `FileSherlock/k15` commit
`ab93479ebc7c85274c722b16897148286d1cfca3`.

This is a source-level review, not a demonstrated remote replay exploit.

## Observed construction

- At `src/os.asm:828-831`, the eleven AES round keys for `prf` are filled once at boot by `rand` into `HKS`.
- At `src/os.asm:2960-2974`, `prf` hashes the client's and server's address/port tuple with those boot-random round keys. Its four output words include `HKO+8`, which the TCP code uses as the cookie secret.
- In the SYN path (around `src/os.asm:2320-2360`), the server sequence/cookie is formed from the client's initial sequence number, `HKO+8`, and the negotiated MSS/window-scale bits.
- At `src/os.asm:2975-2990`, `ckx` recomputes the cookie from the packet's sequence number and `HKO+8`, then compares it with the ACK. The check contains no read of `TNOW`, `NOW`, `BORN`, or any timestamp bucket.
- `tnote`/`tidle` (around `src/os.asm:2725-2795`) timestamp cached SYNs for retransmission. That is a separate retransmission cache; it does not add an age term to `ckx`.

## Narrow conclusion

The frozen cookie is keyed and bound to the address/port tuple and the client's initial sequence number, but the cookie itself has no time component. The key material is initialized at boot, so a reboot changes the key; within one boot, the source does not show a time-based expiry in the cookie verification path.

This makes replay of a previously valid SYN-ACK/ACK exchange a candidate to test within one boot. It does **not** by itself show that an off-path attacker can learn or forge a cookie, bypass TCP sequence checks, hijack an established connection, or obtain TLS secrets. Those are separate questions.

## Safe next test

Build only the frozen image under local QEMU/TAP. Use a synthetic client tuple and fixed ISN, capture its SYN-ACK, complete and close that synthetic connection, then replay the old ACK after a controlled delay and observe whether the server allocates a new slot. Keep all traffic local. Compare the same sequence against the pinned upstream image if its cookie algorithm has changed.

Do not send stale ACKs to `15kb.org`, do not spoof third-party addresses, and do not use production infrastructure.
