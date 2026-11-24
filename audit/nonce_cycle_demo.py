#!/usr/bin/env python3
"""Synthetic demonstration of the RDRAND repetition hypothesis.

This tests the software predicate and ECDSA algebra only. It does not query
RDRAND, contact 15kb.org, or demonstrate that the target hardware is faulty.
"""
from __future__ import annotations

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def signature(d, k, z):
    r = mul(k, G)[0] % N
    s = (z + r * d) * pow(k, -1, N) % N
    return r, s


def main():
    # Four distinct 64-bit words, repeated as a four-word cycle.
    words = (
        0x0123456789ABCDEF,
        0x1029384756ABCDEF,
        0xFEDCBA9876543210,
        0xA5A5A5A55A5A5A5A,
    )
    stream = words * 2

    # Model rand's adjacent-word equality check, including its initial zero.
    previous = 0
    for word in stream:
        assert word != previous, "synthetic stream unexpectedly trips adjacent check"
        previous = word

    # stock consumes four consecutive qwords per 256-bit nonce.
    def nonce_at(offset):
        raw = b"".join(w.to_bytes(8, "little") for w in stream[offset:offset + 4])
        return int.from_bytes(raw, "little")

    k1, k2 = nonce_at(0), nonce_at(4)
    assert k1 == k2
    assert 0 < k1 < N

    # Synthetic private key and two distinct message digests.
    d = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF
    z1 = 0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000
    z2 = 0x9999888877776666555544443333222211110000AAAABBBBCCCCDDDDEEEEFFFF
    assert z1 != z2

    r1, s1 = signature(d, k1, z1)
    r2, s2 = signature(d, k2, z2)
    assert r1 == r2 and s1 != s2

    recovered_k = (z1 - z2) * pow((s1 - s2) % N, -1, N) % N
    recovered_d = (s1 * recovered_k - z1) * pow(r1, -1, N) % N
    assert recovered_k == k1
    assert recovered_d == d

    print("PASS: adjacent 64-bit equality check accepts the four-word cycle")
    print("PASS: two consecutive four-word batches produce the same 256-bit nonce")
    print("PASS: synthetic ECDSA signatures recover the synthetic nonce and private key")
    print("LIMIT: this is an algebra/software-model demonstration, not evidence of a live RDRAND failure")


if __name__ == "__main__":
    main()
