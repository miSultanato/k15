# SITE adjacency and response-read-path review

Date: 2026-11-24

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Question raised in the community

A recent comment noted that the private-key material is located before the
public `SITE` bytes in the image and asked whether a request could read
backwards from the site response into the preceding key material.

Adjacency is real; a network-readable path from `SITE` to preceding image
bytes is not demonstrated by that observation. The relevant question is
whether request-controlled values can become an arbitrary pointer or an
unbounded response index.

## Request path to response index

In `src/os.asm`, the `.pr` lookup:

1. Masks the request-path hash with the generated `PT_MASK`.
2. Reads a fixed-size path-table slot at `SITE + hash_index * 8`.
3. Checks the stored hash.
4. Reads a packer-generated path-record offset.
5. Checks the stored path length and compares the request path byte-for-byte.
6. Loads the response number from the matched path record.

The request controls the hash and the bytes being compared. It does not supply
the path-record offset or the response number directly.

## Response index to bytes

The `geom` routine:

- masks the response number to 15 bits;
- scales it by the fixed 16-byte response-entry size;
- adds the generated `AT_OFF` and `SITE` bases;
- loads the response blob offset and lengths from that packed entry;
- adds `SITE` to the blob offset before setting `TXBLOB` and `TXEND`.

The `pick` routine only selects prepacked plain, compressed, or 304 forms
using response flags and request headers. It does not parse a client-supplied
pointer or a negative offset. Port 80 is even simpler: `respond` copies the
fixed `SITE + P80_OFF` / `P80_LEN` slice emitted by the packer.

## Packer bounds

`tools/pack.py` builds the path table, response entries, path records and
blobs before the image is assembled. It:

- uses a power-of-two path table with at most 50% occupancy;
- rejects more than 32,767 response entries;
- rejects a site larger than 768 MiB;
- stores response offsets and lengths derived from the packed blob layout;
- emits `PT_MASK`, `AT_OFF`, `SITE_LEN` and related constants into
  `site.inc`.

These are build-time values, not values derived from a request.

## Relationship to the private scalar

The private scalar is represented in the runtime image as masked
`d*R mod n` in the generated `EDC` block, copied into `R_D` during
initialization. The strengthened `check_key_read_path.py` now also checks
the `REGC → NLOW → EDC` source layout, the fixed boot copy into `R_D`,
the two fixed `comb` callers and the mask-only table selector. The VM program
that uses `D` is the fixed `X_SIGN` program.

The SITE response path only adds offsets to `SITE`; it has no path that
subtracts from `SITE` or reads a client-selected address before it. Thus the
fact that key-related bytes precede public site bytes does not, by itself,
create a key-disclosure primitive.

## Separate W^X observation

The frozen source has a `%ifdef WXTEST` block that deliberately writes to
and executes the last byte of `SITE` to test page permissions. This is a
test-only compile-time path, not the ordinary HTTP response path. The short
site/page-alignment W^X finding remains separate: executable page placement
does not establish a network-controlled write or a read-before-SITE path.

## Assessment and limits

**Assessment:** no network-reachable SITE-to-preceding-memory read primitive
was found in this targeted source review. The community comment identifies
an adjacency worth auditing, not evidence of key disclosure.

This is a bounded static review of the HTTP path and packer, not a formal
proof of every assembly instruction. It should be kept distinct from the
separate stale-ARP disclosure and TLS framing findings.


## CI validation

The static guard passed as part of the complete bounded-audit workflow on
2026-11-24:
https://github.com/miSultanato/k15/actions/runs/45460761523

The same run also passed the expanded private-scalar source checks, generated
VM include comparison, native RDRAND sample, and Valgrind negative controls.
This validates the authored checks against the pinned bounty source; it is
not a formal proof of the complete binary or runtime.
