"""Example: generate a v1 (pre-RingCT) ring signature and verify it.

This is a *specific, runnable demonstration*, intentionally kept out of the
general ``v1/check_v1.py`` verifier module. It builds a valid CryptoNote v1 ring
signature for a freshly generated key and checks that ``check_v1.check_ring_signature``
accepts it (a prove/verify round-trip).

Run::

    python mic/examples/example_v1_ring_signature.py
"""


import struct

from mic.common import df25519
from mic.common.df25519 import Scalar, Point, PointVector

from mic.v1 import check_v1
def generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index):
    """Produce a CryptoNote v1 ring signature (demonstration prover).

    Mirrors the original Monero generation algorithm: a real L/R pair at the
    signer's secret index and random simulated pairs elsewhere, closed with the
    Fiat-Shamir challenge. Returns ``(image, sigc, sigr)``.
    """
    summ = Scalar(0)
    aba = [Scalar(0) for _ in range(pubs_count)]  # L[i]
    abb = [Scalar(0) for _ in range(pubs_count)]  # R[i]
    sigc = [Scalar(0) for _ in range(pubs_count)]  # the c[i] of the whitepaper
    sigr = [Scalar(0) for _ in range(pubs_count)]  # the r[i] of the whitepaper

    for ii in range(pubs_count):
        Hp = df25519.hash_to_point(str(pubs[ii]))
        if ii == sec_index:
            kk = df25519.random_scalar()
            aba[ii] = df25519.G * kk  # L[s] = kk*G
            abb[ii] = Hp * kk  # R[s] = kk*Hp(P_s)
        else:
            k1 = df25519.random_scalar()  # simulated c[i]
            k2 = df25519.random_scalar()  # simulated r[i]
            aba[ii] = df25519.G * k2 + pubs[ii] * k1  # L[i] = k2*G + k1*P_i
            abb[ii] = Hp * k2 + Point(image) * k1  # R[i] = k2*Hp + k1*I
            sigc[ii] = k1
            sigr[ii] = k2
            summ += sigc[ii]

    buf = struct.pack("64s", prefix)
    for ii in range(pubs_count):
        buf += struct.pack("64s", str(aba[ii]).encode())
        buf += struct.pack("64s", str(abb[ii]).encode())

    c = df25519.hash_to_scalar(buf.decode())
    sigc[sec_index] = c - summ  # c[s] = hash - sum c[i] mod l
    sigr[sec_index] = kk - sigc[sec_index] * sec  # r[s] = kk - c[s]*sec
    return image, sigc, sigr


def main():
    # A 64-byte message prefix (the verifier decodes it as ASCII).
    prefix = b"8ae47e12cca160c1a52e5517f6f1822d2bb6f1a24e8094b78891458f2b3e4d5d"

    # Fresh signer key and the matching key image L = x * Hp(P).
    sec = df25519.random_scalar()
    pub = df25519.G * sec
    image = (df25519.hash_to_point(str(pub)) * sec).b.hex()

    pubs = PointVector([pub])
    _, sigc, sigr = generate_ring_signature(prefix, image, pubs, 1, sec, 0)

    sigc = df25519.ScalarVector(sigc)
    sigr = df25519.ScalarVector(sigr)
    ok = check_v1.check_ring_signature(prefix, image, pubs, 1, sigr, sigc)

    print(f"ring size      : {len(pubs)}")
    print(f"key image      : {image}")
    print(f"signature valid: {ok}")
    assert ok, "round-trip verification failed"


if __name__ == "__main__":
    main()
