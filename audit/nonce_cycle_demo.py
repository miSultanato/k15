#!/usr/bin/env python3
"""Synthetic model of the k15 RDRAND health-check / nonce-batching hypothesis.

The model covers the software boundary only: rand checks adjacent 64-bit
outputs, while stock consumes four outputs for each 256-bit nonce. It does
not query RDRAND, contact 15kb.org, or show that any real CPU is faulty.
"""
from __future__ import annotations

from math import gcd

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
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


def nonce_from_words(words):
    """Match four qword stores interpreted as one 256-bit little-endian value."""
    raw = b"".join(word.to_bytes(8, "little") for word in words)
    return int.from_bytes(raw, "little")


def check_periodic_stream(period):
    """Model consecutive stock() batches, with no other rand() call interleaved.

    A period-p stream repeats a four-qword nonce after p/gcd(p,4) batches.
    """
    assert len(period) > 1
    assert len(set(period)) == len(period)
    assert period[0] != 0
    assert period[-1] != period[0]  # no equal value across the period boundary

    batch_period = len(period) // gcd(len(period), 4)
    stream = [period[i % len(period)] for i in range(4 * (batch_period + 1))]

    # Model rand's per-processor RLAST check with the preceding cycle word
    # already stored in RLAST (the runtime state after boot).
    previous = period[-1]
    for word in stream:
        assert word != previous, "periodic stream unexpectedly trips adjacent check"
        previous = word

    first = nonce_from_words(stream[0:4])
    repeated = nonce_from_words(stream[4 * batch_period:4 * batch_period + 4])
    assert first == repeated
    return batch_period


def main():
    # Explore periods 2..8 and 16. Every period is deliberately composed of
    # distinct words, so the adjacent-equality check accepts every transition.
    periods = (2, 3, 4, 5, 6, 7, 8, 16)
    for size in periods:
        values = tuple(0x1020304050607000 + i * 0x0101010101010101
                       for i in range(size))
        batches = check_periodic_stream(values)
        print(f"PASS: period {size} evades adjacent check; a nonce repeats after {batches} batches")

    # The four-word case gives an immediately repeated nonce, suitable for the
    # synthetic ECDSA key-recovery demonstration below.
    words = (
        0x0123456789ABCDEF,
        0x1029384756ABCDEF,
        0xFEDCBA9876543210,
        0xA5A5A5A55A5A5A5A,
    )
    # Boot consumed 22 qwords into HKS. Each TLS handshake additionally
    # consumes 8 qwords (4 for the X25519 scalar and 4 for ServerHello.random).
    # Simulate one stock nonce replenishment per handshake. For period 4,
    # both the 22-qword prefix and 8-qword interleaving preserve batch phase.
    previous = words[(22 - 1) % 4]
    stream_index = 22
    interleaved_nonces = []
    for _ in range(5):
        for _ in range(8):
            word = words[stream_index % 4]
            assert word != previous
            previous = word
            stream_index += 1
        nonce_words = []
        for _ in range(4):
            word = words[stream_index % 4]
            assert word != previous
            previous = word
            nonce_words.append(word)
            stream_index += 1
        interleaved_nonces.append(nonce_from_words(nonce_words))
    assert len(set(interleaved_nonces)) == 1

    k1 = interleaved_nonces[0]
    k2 = interleaved_nonces[1]
    assert 0 < k1 < N and k1 == k2

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

    print("PASS: period-4 nonce repeats persist with 8 handshake-random qwords interleaved")
    print("PASS: synthetic ECDSA signatures recover the synthetic nonce and private key")
    print("LIMIT: this is a software/algebra model, not evidence of a live RDRAND failure")


if __name__ == "__main__":
    main()
