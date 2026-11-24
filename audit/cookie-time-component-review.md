# Frozen-source review: TCP SYN cookie time component

Date: 2026-11-24

Target: `FileSherlock/k15` commit
`ab93479ebc7c85274c722b16897148286d1cfca3`.

This is a source-level review, not a demonstrated remote replay exploit.

## Observed construction

- At `src/os.asm:828-831`, the eleven AES round keys for `prf` are filled once at boot by `rand` into `HKS`.
- At `src/os.asm:2960-2974`, `prf` hashes the client's and server's address/port tuple with those boot-random round keys. Its four output words include `HKO+8`, which the TCP code uses as the cookie secret.
- In the SYN path (around `src/os.asm:1498-1520`), the server sequence/cookie is formed from the client's initial sequence number, `HKO+8`, and the negotiated MSS/window-scale bits.
- At `src/os.asm:2975-2990`, `ckx` recomputes the cookie from the packet's sequence number and `HKO+8`, then compares it with the ACK. The check contains no read of `TNOW`, `NOW`, `BORN`, or any timestamp bucket.
- `tnote`/`tidle` (around `src/os.asm:2725-2795`) timestamp cached SYNs for retransmission. That is a separate retransmission cache; it does not add an age term to `ckx`.

## Narrow conclusion

The frozen cookie is keyed and bound to the address/port tuple and the client's initial sequence number, but the cookie itself has no time component. The key material is initialized at boot, so a reboot changes the key; within one boot, the source does not show a time-based expiry in the cookie verification path.

A local TAP test now holds a synthetic SYN-ACK for 65 seconds before sending its first ACK. The frozen bounty and first upstream fix both accept that delayed ACK and process a following HTTP request; the current-upstream image also accepts the delayed ACK. This demonstrates no 64-second cookie expiry in the tested revisions. It is **not** a replay after connection teardown and does not show that an off-path attacker can learn or forge a cookie, bypass TCP sequence checks, hijack an established connection, or obtain TLS secrets.

## Local teardown/replay experiment

[Run 45443282691](https://github.com/miSultanato/k15/actions/runs/45443282691) completes a local port-80 exchange and a full client-FIN/server-FIN close on all three pinned images. It then replays the original cookie ACK and sends a request with a different length. The server ACK equals the new request's end sequence on all three, proving that the replay created a fresh slot and the new payload was consumed.

That response alone is **not conclusive**: the port-80 handler serves one fixed response and does not distinguish request methods or paths. A retransmission of the old response could look identical to a newly allocated connection. [Three-way run 45443936657](https://github.com/miSultanato/k15/actions/runs/45443936657) adds a 65-second wait after the completed teardown before replaying that same cookie. All three images accept the replay and acknowledge the longer second request at its exact end sequence. The cookie therefore remains replayable for at least 65 seconds after teardown in these local tests.

## Safe scope

Run only local images under QEMU/TAP. Compare the frozen image with the two pinned upstream revisions. Do not send stale ACKs to `15kb.org`, spoof third-party addresses, or use production infrastructure.

Do not send stale ACKs to `15kb.org`, do not spoof third-party addresses, and do not use production infrastructure.
