# Per-processor connection affinity review

Date: 2026-11-24

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Result

**A client can make repeated connections with the same four-tuple land on the same processor, but cannot choose which processor from source code or tuple alone.** This is a deterministic routing property, not a demonstrated vulnerability.

The finding refines the open question in `community-watch-2026-11-24.md`: connection affinity is stable and partly client-influenceable, while processor identity is hidden behind a boot-time keyed hash.

## Source trace

1. During boot, `src/os.asm` calls `rand` with `ecx = 22` and `EDI = HKS` (around lines 828–832). This fills the 176-byte AES round-key schedule used by `prf`.
2. The first processor later counts the APs and sets `NCPUM` to one less than the largest power of two not exceeding the processor count (around lines 935–946). With two active processors, `NCPUM = 1`; with four, `NCPUM = 3`.
3. `drain` computes `prf` for each received frame when more than one processor is active (around lines 1050–1058). It takes dword 3 of the AES result and masks it with `NCPUM` to choose the destination processor's ring.
4. `prf` (around lines 2960–2973) takes the 12-byte address/port tuple, shifts it into an AES block, XORs the boot-time `HKS` schedule and applies ten AES rounds.
5. `apstart` assigns each processor its own ring using `CPUN` and `RSTEP` (around lines 1143–1147). The per-processor BSS model keeps its nonce pool and `RLAST` local.

The routing input is the network tuple, not the TCP sequence number or TLS handshake contents. Therefore, within one boot, an identical source/destination address-and-port tuple produces the same PRF output and is assigned to the same processor.

## What a remote client controls

- The client normally controls its source address and source port; the destination is the published service.
- Reusing the same four-tuple for sequential connections therefore pins those connections to one (unknown) processor.
- Changing the tuple changes the AES input, but the output-to-processor mapping depends on the secret boot-time `HKS` schedule.
- No CPU identifier is returned in a packet, and the source contains no direct remote oracle that reveals the selected `CPUN`.

This means a client can concentrate its own sequential traffic on one stable processor without knowing which processor it is. It cannot, from the tuple alone, select CPU 0 versus CPU 1 or predict the mapping before the boot-time key is known.

The previously reproduced same-tuple SYN-cookie replay after FIN/FIN teardown is consistent with reusing a tuple, but it is not required for the affinity property: the routing hash itself is tuple-based. The replay observation remains a separate, common-to-all-revisions protocol property documented in `syn-cookie-replay-observation.md`.

## Relevance to the nonce hypothesis

The nonce pool, `RLAST`, and curve state are processor-local. Stable tuple affinity therefore means a client can keep repeated handshakes on one processor if it can reuse the same four-tuple sequentially. This is relevant if a processor-specific RNG anomaly were independently established.

It does **not** establish any of the following:

- that one processor's RDRAND stream is weaker than another's;
- that a remote client can cause or predict an RDRAND failure;
- that the client can identify which processor its tuple selects;
- that the boot-time AES PRF is recoverable;
- that repeated handshakes expose a nonce or the private scalar.

The hash is keyed with boot-time random material. Without an oracle for processor identity, selecting a tuple for a particular processor is not supported by the current evidence. Timing or load-based CPU identification would be a separate side-channel hypothesis and has not been tested.

## Classification

**Status: source-level routing property confirmed; targeted processor steering unproven.**

This closes the static part of the affinity question but not the possibility of an external timing oracle. No production traffic, load testing, or server disruption was performed.

A deterministic local QEMU test could expose ring selection for chosen tuples under synthetic `HKS` material, but it would only confirm the source mapping. It would not reveal the production boot key or establish a remote CPU-identification oracle, so it is not currently a high-priority test.
