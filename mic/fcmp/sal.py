"""
MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments
This project incorporates [monero-oxide](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

FCMP++ Spend-Authorization & Linkability (SAL) proof.

An input being spent is opened as an OpenedInputTuple:
    O~ = x G + y T        (y = r_o + y_orig)
    I~ = I + r_i U        (I = Hp(O))
    R  = r_i V + r_r_i T
    C~ = C + r_c G

The SAL proves knowledge of (x, y, r_i, r_r_i) binding the spend to
signable_tx_hash, and returns the consensus key image L = x * I = x * Hp(O).

Wire format (384 bytes): P A B R_O R_P R_L (6 points) ‖ s_alpha s_beta s_delta
s_y s_z s_r_p (6 scalars).
"""



import hashlib
from dataclasses import dataclass

import nacl.bindings
from mic.common import df25519
from mic.common.df25519 import Scalar, Point

from mic.txlib.carrot import T, U, V

G = df25519.G
Z = df25519.Z
_ONE = Scalar(1)


def _reduce64(b: bytes) -> Scalar:
    return Scalar(nacl.bindings.crypto_core_ed25519_scalar_reduce(b))


def _challenge(signable_tx_hash, O_t, I_t, R, C_t, L, P, A, B, R_O, R_P, R_L) -> Scalar:
    h = hashlib.blake2b(digest_size=64)
    h.update(signable_tx_hash)
    # Input::transcript order: O~, I~, C~, R, L
    h.update(O_t)
    h.update(I_t)
    h.update(C_t)
    h.update(R)
    h.update(L)
    h.update(P)
    h.update(A)
    h.update(B)
    h.update(R_O)
    h.update(R_P)
    h.update(R_L)
    return _reduce64(h.digest())


@dataclass
class SAL:
    P: bytes
    A: bytes
    B: bytes
    R_O: bytes
    R_P: bytes
    R_L: bytes
    s_alpha: Scalar
    s_beta: Scalar
    s_delta: Scalar
    s_y: Scalar
    s_z: Scalar
    s_r_p: Scalar

    SIZE = 12 * 32  # 6 points + 6 scalars

    def to_bytes(self) -> bytes:
        return (
            self.P
            + self.A
            + self.B
            + self.R_O
            + self.R_P
            + self.R_L
            + self.s_alpha.b
            + self.s_beta.b
            + self.s_delta.b
            + self.s_y.b
            + self.s_z.b
            + self.s_r_p.b
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> "SAL":
        """Parse the 384-byte wire form (as it appears inside a tx's fcmp_pp blob).

        Inverse of to_bytes: 6 compressed points followed by 6 scalars, in the
        order P A B R_O R_P R_L ‖ s_alpha s_beta s_delta s_y s_z s_r_p.
        """
        if len(b) != cls.SIZE:
            raise ValueError(f"SAL proof must be {cls.SIZE} bytes, got {len(b)}")
        f = [b[i * 32 : (i + 1) * 32] for i in range(12)]
        return cls(f[0], f[1], f[2], f[3], f[4], f[5], *[Scalar(x) for x in f[6:]])


def prove(
    signable_tx_hash: bytes,
    O_tilde: bytes,
    I_tilde: bytes,
    R: bytes,
    C_tilde: bytes,
    x: Scalar,
    y: Scalar,
    r_i: Scalar,
    r_r_i: Scalar,
    *,
    rng=None,
):
    """Returns (L_point, SAL).  L is the consensus key image."""
    rand = rng or df25519.random_scalar
    I_t = Point(I_tilde)

    # L = I~ x - U (r_i x)
    L = (I_t * x) - (U * (r_i * x))

    alpha = rand()
    beta = rand()
    delta = rand()
    mu = rand()
    r_y = rand()
    r_z = rand()
    r_p = rand()
    r_r_p = rand()

    x_r_i = x * r_i

    P = (G * x) + (V * r_i) + (U * x_r_i) + (T * r_p)
    alpha_G = G * alpha
    A = alpha_G + (V * beta) + (U * ((alpha * r_i) + (beta * x))) + (T * delta)
    B = (U * (alpha * beta)) + (T * mu)
    R_O = alpha_G + (T * r_y)
    R_P = (U * r_z) + (T * r_r_p)
    R_L = (I_t * alpha) - (U * r_z)

    e = _challenge(
        signable_tx_hash, O_tilde, I_tilde, R, C_tilde, L.b, P.b, A.b, B.b, R_O.b, R_P.b, R_L.b
    )

    s_alpha = alpha + (e * x)
    s_beta = beta + (e * r_i)
    s_delta = mu + (e * delta) + (r_p * (e * e))
    s_y = r_y + (e * y)
    s_z = r_z + (e * x_r_i)
    r_p_dq = r_p - y - r_r_i
    s_r_p = r_r_p + (e * r_p_dq)

    return L, SAL(P.b, A.b, B.b, R_O.b, R_P.b, R_L.b, s_alpha, s_beta, s_delta, s_y, s_z, s_r_p)


def _lincomb(terms):
    acc = Z
    for s, P in terms:
        acc = acc + (P * s)
    return acc


def verify(
    signable_tx_hash: bytes,
    O_tilde: bytes,
    I_tilde: bytes,
    R: bytes,
    C_tilde: bytes,
    L: Point,
    sal: SAL,
) -> bool:
    O_t = Point(O_tilde)
    I_t = Point(I_tilde)
    R_pt = Point(R)
    P = Point(sal.P)
    A = Point(sal.A)
    B = Point(sal.B)
    R_O = Point(sal.R_O)
    R_P = Point(sal.R_P)
    R_L = Point(sal.R_L)

    e = _challenge(
        signable_tx_hash,
        O_tilde,
        I_tilde,
        R,
        C_tilde,
        L.b,
        sal.P,
        sal.A,
        sal.B,
        sal.R_O,
        sal.R_P,
        sal.R_L,
    )
    ee = e * e
    sa, sb, sd = sal.s_alpha, sal.s_beta, sal.s_delta
    sy, sz, srp = sal.s_y, sal.s_z, sal.s_r_p

    c1 = _lincomb(
        [(ee, P), (e, A), (_ONE, B), (-(sa * e), G), (-(sb * e), V), (-(sa * sb), U), (-sd, T)]
    )
    c2 = _lincomb([(_ONE, R_O), (e, O_t), (-sa, G), (-sy, T)])
    c3 = _lincomb([(_ONE, R_P), (e, (P - O_t - R_pt)), (-sz, U), (-srp, T)])
    c4 = _lincomb([(_ONE, R_L), (e, L), (-sa, I_t), (sz, U)])
    return c1 == Z and c2 == Z and c3 == Z and c4 == Z


if __name__ == "__main__":
    # self-test: build a consistent opened input tuple and prove/verify
    from mic.txlib.carrot import hash_to_point_biased
    import os

    ok_all = True
    for _ in range(5):
        x = df25519.random_scalar()
        y = df25519.random_scalar()
        r_i = df25519.random_scalar()
        r_r_i = df25519.random_scalar()
        r_c = df25519.random_scalar()

        O_tilde = (G * x) + (T * y)  # O~ = xG + yT
        O_for_I = G * x  # (Hp anchor, arbitrary for the algebra)
        I = hash_to_point_biased(O_for_I.b)  # I = Hp(O)
        I_tilde = I + (U * r_i)  # I~ = I + r_i U
        R = (V * r_i) + (T * r_r_i)  # R  = r_i V + r_r_i T
        C_tilde = G * r_c  # C~ (unused in algebra)

        sig = os.urandom(32)
        L, sal = prove(sig, O_tilde.b, I_tilde.b, R.b, C_tilde.b, x, y, r_i, r_r_i)
        # key image consistency: L == x * I  (= x * Hp(O))
        ki_ok = L == (I * x)
        v_ok = verify(sig, O_tilde.b, I_tilde.b, R.b, C_tilde.b, L, sal)
        size_ok = len(sal.to_bytes()) == 384
        print(f"verify={v_ok} key_image L==x*I:{ki_ok} size={len(sal.to_bytes())}")
        ok_all &= v_ok and ki_ok and size_ok
    print("SAL SELF-TEST:", "PASS" if ok_all else "FAIL")
