"""
MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments
This project incorporates [monero-oxide](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

Re-randomization + membership-proof blinds (output blinds & branch blinds).

The re-randomization scalars (r_o, r_i, r_r_i, r_c) bridge the SAL proof and the
FCMP membership proof. The membership blinds are:
    o_blind = -r_o,  i_blind = -r_i,  i_blind_blind = r_r_i,  c_blind = -r_c.

"""



from mic.common import df25519
from mic.common.df25519 import Scalar

from mic.fcmp.divisors import ScalarDecomposition
from mic.fcmp.proof import (
    OBlind,
    IBlind,
    IBlindBlind,
    CBlind,
    OutputBlinds,
    BranchBlind,
    PreparedBlind,
    ScalarMulAndDivisor,
)
from mic.fcmp.field import HeliosField, SeleneField
from mic.fcmp.curve import (
    ED25519_L,
    HELIOS,
    SELENE,
    WEI25519,
    ProjectivePoint,
    oc_from_bytes,
)

from mic.txlib import carrot
L = ED25519_L


def _wei(point_bytes: bytes) -> ProjectivePoint:
    xy = oc_from_bytes(point_bytes)
    if xy is None:
        raise ValueError("generator failed OC conversion")
    x, y = xy
    return WEI25519.point(x.v, y.v)


# OC generators as Wei25519 points (consensus G, T, U, V)
G_WEI = _wei(df25519.G.b)
T_WEI = _wei(carrot.T.b)
U_WEI = _wei(carrot.U.b)
V_WEI = _wei(carrot.V.b)


class Rerandomization:
    """The four re-randomization scalars and the resulting blinded tuple."""

    def __init__(self, O: bytes, I: bytes, C: bytes, rng=None, r_c: Scalar = None):
        rand = rng or df25519.random_scalar
        self.r_o = rand()
        self.r_i = rand()
        self.r_r_i = rand()
        # r_c is fixed by the output balance (r_c = Σ k_a − z_in), random only for tests
        self.r_c = r_c if r_c is not None else rand()
        Op, Ip, Cp = df25519.Point(O), df25519.Point(I), df25519.Point(C)
        # O~ = O + T r_o,  I~ = I + U r_i,  R = V r_i + T r_r_i,  C~ = C + G r_c
        self.O_tilde = (Op + carrot.T * self.r_o).b
        self.I_tilde = (Ip + carrot.U * self.r_i).b
        self.R = (carrot.V * self.r_i + carrot.T * self.r_r_i).b
        self.C_tilde = (Cp + df25519.G * self.r_c).b

    def _neg(self, s: Scalar) -> int:
        return (L - (s.to_int() % L)) % L

    def output_blinds(self) -> OutputBlinds:
        o = ScalarDecomposition(self._neg(self.r_o) or 1)
        i = ScalarDecomposition(self._neg(self.r_i) or 1)
        ibb = ScalarDecomposition(self.r_r_i.to_int() % L or 1)
        c = ScalarDecomposition(self._neg(self.r_c) or 1)
        return OutputBlinds(
            OBlind.new(T_WEI, o),
            IBlind.new(U_WEI, V_WEI, i),
            IBlindBlind.new(T_WEI, ibb),
            CBlind.new(G_WEI, c),
        )


def build_branch_blinds(params, layers: int, n_inputs: int = 1, rng=None):
    """C1 (Selene) and C2 (Helios) branch blinds.
    counts: n_c1 = n_inputs*(layers//2), n_c2 = n_inputs*((layers-1)//2)."""
    rand = rng or (lambda: __import__("secrets").randbits(256))
    n_c1 = n_inputs * (layers // 2)
    n_c2 = n_inputs * ((layers - 1) // 2)
    H_sel = params.curve_1_generators.h()
    H_hel = params.curve_2_generators.h()

    b1 = []
    for _ in range(n_c1):
        s = rand() % HeliosField.P or 1
        decomp = ScalarDecomposition(s, SELENE)
        b1.append(BranchBlind(PreparedBlind(decomp, ScalarMulAndDivisor.new_c1(H_sel, decomp))))
    b2 = []
    for _ in range(n_c2):
        s = rand() % SeleneField.P or 1
        decomp = ScalarDecomposition(s, HELIOS)
        b2.append(BranchBlind(PreparedBlind(decomp, ScalarMulAndDivisor.new_c2(H_hel, decomp))))
    return b1, b2


if __name__ == "__main__":
    # sanity: re-randomization matches SAL (O~ = O + T r_o) and blind() round-trips
    import time

    O = (df25519.G * df25519.random_scalar()).b
    I = carrot.hash_to_point_unbiased(O).b
    C = (df25519.G * df25519.random_scalar()).b
    rr = Rerandomization(O, I, C)
    print("O~,I~,R,C~ computed.")
    t = time.time()
    ob = rr.output_blinds()
    print(f"output_blinds (5 divisors) built in {time.time()-t:.1f}s")
    blinded = ob.blind(oc_from_bytes(O), oc_from_bytes(I), oc_from_bytes(C))
    print("blind() keys:", list(blinded.keys()))
    print("O~ match:", blinded["O_tilde"] == rr.O_tilde)
