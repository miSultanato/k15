# ECDSA nonce range-conversion review

Date: 2026-11-24

Target: frozen bounty source
`ab93479ebc7c85274c722b16897148286d1cfca3`.

## Result

**Confirmed source-level nonce-distribution bias; no practical key-recovery exploit demonstrated.**

The frozen signer consumes four RDRAND qwords as one 256-bit candidate nonce. It does not reject candidates greater than or equal to the P-256 subgroup order (n). The curve multiplication and modular inversion make the effective ECDSA nonce behave as (K \bmod n). Since the 256-bit candidate space is only slightly larger than (n), this introduces a small but exact modulo-reduction bias.

This is separate from nonce reuse and from the synthetic periodic-stream hypothesis. It does not show that the production CPU is faulty or that an attacker can recover the private key.

## Source path

- `src/os.asm`, `stock`: calls `rand` with `ecx = 4`, placing four consecutive qwords in `POOLK`.
- `src/os.asm`, `sign`: consumes the precomputed point and inverse for one nonce.
- `tools/ec.py`, `sign`: `k2 = self.sub(k, KOFF)` is explicitly weakly reduced modulo `N256`; `self.inv(k)` is performed in `FN256), whose modulus is (n).
- `tools/ec.py`, `SIGN`: computes the ECDSA scalar arithmetic modulo (n).
- `audit/test_ecdsa_nonce_boundaries.py`: the frozen assembly signer produces the same valid signature for (k=n+1) as for (k=1), confirming the effective scalar alias; (k=n) produces no valid signature.

The alias test is important: this is not merely an assumption based on the mathematical group order. The actual frozen assembly signer has been exercised at these boundaries.

## Exact distribution

Let:

- (R = 2^{256}), the size of the four-qword candidate space;
- (n) be the P-256 subgroup order;
- (\Delta = R-n).

For a uniformly distributed raw candidate (K\in[0,R-1]), the effective scalar is (k=K\bmod n).

For every (k\in[0,\Delta-1]), there are **two** raw candidates that map to it: (K=k) and (K=k+n). For every (k\in[\Delta,n-1]), there is only one. Therefore the low interval receives twice the probability mass of an ideal uniform draw from the subgroup.

For the exact P-256 order in the source:

```text
n     = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Delta = 2^256 - n
      = 0xFFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
```

`Delta < 2^224`, so the affected interval consists of effective nonce values whose top 32 bits are zero.

- Probability of a raw candidate overflowing the order ((K\ge n)): (\Delta/2^{256}\), approximately (2^{-32}).
- Probability that the effective nonce falls in the low interval ([0,\Delta-1]): (2\Delta/2^{256}\), approximately (2^{-31}).
- Under an ideal uniform draw from ([1,n-1]), that interval would occur with probability approximately (\Delta/n\), or (2^{-32}).

Thus the low-224-bit interval is approximately twice as likely as it should be. The excess probability mass is approximately one event per (2^{32}) signatures. This is a genuine distribution deviation, but it is sparse.

Reproduce the arithmetic with Python's standard library:

```python
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
R = 1 << 256
delta = R - n
print(hex(delta))
print("overflow probability:", delta / R)
print("effective low-interval probability:", 2 * delta / R)
print("ideal low-interval probability:", delta / n)
print("relative factor:", (2 * delta / R) / (delta / n))
```

## Standards context

NIST FIPS 186-5 §A.3 describes generation of ECDSA per-message secret numbers in ([1,n-1]). Its two specified approaches are rejection sampling or conversion using at least 64 additional random bits so that reduction bias is negligible. The frozen implementation uses a 256-bit candidate for a 256-bit order and neither rejects (K\ge n) nor obtains those extra bits.

RFC 6979 §2.4 describes the standard randomized ECDSA nonce as a uniform selection from the modular range and specifies that the point's x-coordinate is reduced modulo the subgroup order. The project does not claim FIPS validation; this is a cryptographic-hygiene/conformance observation, not a claim of certification failure.

References:

- NIST, FIPS 186-5, Appendix A.3: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
- RFC 6979, §3.2: https://datatracker.ietf.org/doc/rfc6979/

## What this does and does not mean

Established:

- The frozen implementation accepts raw 256-bit candidates without range rejection.
- Its effective ECDSA scalar arithmetic aliases candidates modulo (n).
- The resulting nonce distribution is not exactly uniform.
- The bias is concentrated in a tiny interval of size approximately (2^{224}), with the top 32 bits zero.
- The existing 4,096-nonce community sample would have an expected probability of only about (1.9\times10^{-6}) of containing even one nonce in that interval. Its reported absence of detectable bias does not test or contradict this rare event.

Not established:

- That the production RDRAND stream has any defect.
- That the rare low-interval samples can be identified efficiently from public signatures.
- That one such sample, or the distribution deviation by itself, is sufficient to recover the signing scalar.
- That a practical lattice/HNP attack can exploit this sparse bias within the bounty rules.
- Any key disclosure, signature forgery, or production impact.

A single nonce with 32 known high bits would not by itself reveal a 256-bit signing scalar. A useful lattice attack would need enough exploitable samples and a way to identify or jointly model them. No such attack has been demonstrated here. The published independent statistical report is self-reported and its sample is far too small to assess this particular (2^{-32})-scale excess.

## Classification and next step

**Classification: low-severity cryptographic distribution defect / standards-hygiene gap. Not a confirmed bounty vulnerability.**

A future non-bounty implementation could reject (K=0) and (K\ge n) and draw another candidate, or use a documented bias-minimizing conversion. No change is made to the frozen `bounty` branch, and this review does not authorize any production traffic or load testing.

The separate observation that `FIN256` returns the raw x-coordinate rather than explicitly reducing it modulo (n) is even rarer for P-256 ((p-n\) is only about (2^{-130}) of the field range). It is not the source of the nonce-distribution bias above and is not treated as a practical finding here.
