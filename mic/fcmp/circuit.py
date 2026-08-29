"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

circuit.py - the FCMP++ circuit.

"""

from mic.fcmp.gbp import ArithmeticCircuitStatement, ArithmeticCircuitWitness, ScalarVector
from mic.fcmp.r1cs import R1CS, Lc, Witness, as_wire as _to_var
from mic.fcmp import gadgets


class DlogParams:
    """Computed DiscreteLogParameters for a given ScalarBits value."""

    def __init__(self, scalar_bits: int):
        self.scalar_bits = scalar_bits
        self.x_coefficients = (scalar_bits + 1) // 2
        self.x_coefficients_minus_1 = self.x_coefficients - 1
        self.yx_coefficients = (scalar_bits + 2) // 2 - 2


OC_PARAMS = DlogParams(253)  # Ed25519 group order: NUM_BITS = 253
C1_PARAMS = DlogParams(255)  # SeleneField:    NUM_BITS = 255
C2_PARAMS = DlogParams(255)  # HeliosField:         NUM_BITS = 255


class CurveSpec:
    """Short Weierstrass curve y^2 = x^3 + a*x + b, as circuit-side field elements."""

    def __init__(self, a, b):
        self.a = a
        self.b = b

    @classmethod
    def for_curve(cls, curve):
        """Build from a curve descriptor (curve.py), the source of truth for a and b."""
        return cls(curve.field_cls(curve.a), curve.field_cls(curve.b))


class Divisor:
    """
    Holds circuit Variable references for one divisor polynomial.

    y                  : Variable, coefficient of y^1 x^0
    yx                 : list[Variable], coefficients of y x^i (i=1..YxCoeff, skips i=0)
    x_from_power_of_2  : list[Variable], coefficients of x^i (i=2..XCoeff, skips x^1)
    zero               : Variable, constant term (y^0 x^0)
    """

    def __init__(self, y, yx, x_from_power_of_2, zero):
        self.y = _to_var(y)
        self.yx = [_to_var(v) for v in yx]
        self.x_from_power_of_2 = [_to_var(v) for v in x_from_power_of_2]
        self.zero = _to_var(zero)

    @classmethod
    def from_tape_dict(cls, d):
        """Build from the dict returned by tape.append_divisor()."""
        return cls(
            y=d["y"],
            yx=d["yx"],
            x_from_power_of_2=d["x_from_power_of_2"],
            zero=d["zero"],
        )


class PointWithDlog:
    """
    Holds circuit Variable references for a point with a discrete log proof.

    dlog    : list[Variable], ScalarBits bit-decomposition variables
    divisor : Divisor
    point   : (Variable, Variable), i.e. (x_var, y_var)
    """

    def __init__(self, dlog, divisor, point):
        # Convert in-place so list identity is preserved for shared-dlog cases
        for i, v in enumerate(dlog):
            if not isinstance(v, tuple):
                dlog[i] = _to_var(v)
        self.dlog = dlog
        self.divisor = divisor
        self.point = (_to_var(point[0]), _to_var(point[1]))


class GeneratorTable:
    """
    Precomputed table: table[i] = 2^i * generator.
    Uses mdbl-2007-bl Jacobian doubling, normalized to affine at each step.
    """

    def __init__(self, curve: CurveSpec, gx, gy, scalar_bits: int):
        lhs = gy * gy
        rhs = gx * gx * gx + curve.a * gx + curve.b
        if lhs != rhs:
            raise ValueError("generator base point is not on the specified curve")
        self.scalar_bits = scalar_bits
        table = [(gx, gy)]
        for _ in range(1, scalar_bits):
            table.append(GeneratorTable._dbl(curve.a, *table[-1]))
        self.table = table

    @staticmethod
    def _dbl(a, x1, y1):
        """mdbl-2007-bl: affine output."""
        xx = x1 * x1
        # w = a + 3*xx
        w = a + xx + xx + xx
        y1y1 = y1 * y1
        r = y1y1 + y1y1  # 2*y1^2
        # sss = (y1*r).double().double() = 4 * y1 * r
        yr = y1 * r
        sss = yr + yr
        sss = sss + sss
        rr = r * r
        b = x1 + r
        b = b * b - xx - rr  # 4*x1*y1^2
        h = w * w - b - b  # w^2 - 2*b
        x3j = (h + h) * y1  # 2*h*y1
        y3j = w * (b - h) - rr - rr  # w*(b-h) - 2*rr
        z3 = sss  # 8*y1^3
        z3i = z3.inv()
        return (x3j * z3i, y3j * z3i)


class ChallengePoint:
    """
    Precomputed challenge-evaluation helpers for one point.
    """

    def __init__(self, curve: CurveSpec, slope, x, y, inv_two_y, dlog_params: DlogParams):
        x_count = dlog_params.x_coefficients
        yx_count = dlog_params.yx_coefficients

        # x_pows[0]=x, x_pows[i]=x^(i+1), length = x_count
        x_pows = [None] * x_count
        x_pows[0] = x
        for i in range(1, x_count):
            x_pows[i] = x_pows[i - 1] * x

        # yx[0]=y*x, yx[i]=y*x^(i+1), length = yx_count, skips y*x^0
        yx = [None] * yx_count
        yx[0] = y * x
        for i in range(1, yx_count):
            yx[i] = yx[i - 1] * x

        xx = x * x
        three_x_sq_a = xx + xx + xx + curve.a  # 3x^2 + a
        two_y = y + y

        p_0_n_0 = three_x_sq_a * inv_two_y

        # x_p_0_n_0[i] = p_0_n_0 * x_pows[i],  length = yx_count
        x_p_0_n_0 = [p_0_n_0 * x_pows[i] for i in range(yx_count)]

        # p_1_n = 2*y,  p_1_d = (-slope)*p_1_n + 3x^2+a
        p_1_n = two_y
        p_1_d = (-slope) * p_1_n + three_x_sq_a

        self.y = y
        self.yx = yx
        self.x = x_pows
        self.p_0_n_0 = p_0_n_0
        self.x_p_0_n_0 = x_p_0_n_0
        self.p_1_n = p_1_n
        self.p_1_d = p_1_d


class DiscreteLogChallenge:
    """Three challenge points + line parameters."""

    def __init__(self, c0, c1, c2, slope, intercept):
        self.c0 = c0
        self.c1 = c1
        self.c2 = c2
        self.slope = slope
        self.intercept = intercept


class ChallengedGenerator:
    """Inverted (intercept - (G_i.y - slope*G_i.x)) for each bit i."""

    def __init__(self, weights):
        self.weights = weights  # list[F], length = ScalarBits


def _batch_invert(values):
    """Montgomery's trick: invert a list of field elements in ~1 inverse."""
    n = len(values)
    if n == 0:
        return []
    prefix = [None] * n
    prefix[0] = values[0]
    for i in range(1, n):
        prefix[i] = prefix[i - 1] * values[i]
    inv_total = prefix[-1].inv()
    result = [None] * n
    for i in range(n - 1, 0, -1):
        result[i] = inv_total * prefix[i - 1]
        inv_total = inv_total * values[i]
    result[0] = inv_total
    return result


class Circuit:
    """One per-curve constraint system

    field_cls    : HeliosField | SeleneField, the circuit's scalar field
    commitments  : the Pedersen vector commitments the CG wires read (prover only)
    """

    def __init__(self, field_cls: type, commitments=None, proving: bool = False):
        self.F = field_cls
        witness = Witness(commitments) if proving else None
        self.cs = R1CS(field_cls, witness)

    @classmethod
    def prove(cls, field_cls: type, commitments) -> "Circuit":
        return cls(field_cls, commitments, proving=True)

    @classmethod
    def verify(cls, field_cls: type) -> "Circuit":
        return cls(field_cls, None, proving=False)

    @property
    def constraints(self) -> list:
        # the linear rows, in emission order: what the argument folds
        return self.cs.constraints

    @property
    def blocks(self) -> list:
        # per-gadget row attribution, see r1cs.Block
        return self.cs.blocks

    @property
    def muls_count(self) -> int:
        return self.cs.n_mul

    @property
    def prover_data(self):
        # the witness, or None when verifying
        return self.cs.witness

    def eval(self, lc: Lc):
        return self.cs.eval(lc)

    # -- layer entry points (called by fcmp.py) --------------------------

    def new_wires(self, witness=None) -> tuple:
        """Two fresh, initially unconstrained wires. See r1cs.R1CS.new_wires.

        Used for a cross-curve node hash's coordinates, which the layer's own rows
        then pin.
        """
        return self.cs.new_wires(witness)

    def first_layer(self, *args, **kwargs):
        return gadgets.first_layer(self.cs, *args, **kwargs)

    def additional_layer(self, *args, **kwargs):
        return gadgets.additional_layer(self.cs, *args, **kwargs)

    def additional_layer_discrete_log_challenge(self, transcript, curve, H_table):
        return gadgets.additional_layer_discrete_log_challenge(self.cs, transcript, curve, H_table)

    # -- hand off to Generalized Bulletproofs ------------------------------

    def statement(self, generators, commitment_points) -> tuple:
        """Package the system (and the witness, when proving) for the argument.

        The engine takes only the linear rows: the multiplication rows
        aL_i · aR_i = aO_i are enforced structurally by the proof, not folded
        (see the module docstring of r1cs.py).
        """
        stmt = ArithmeticCircuitStatement(
            generators, self.cs.linear_rows(), commitment_points, []
        )

        witness = None
        if self.cs.witness is not None:
            w = self.cs.witness
            aL = ScalarVector(w.aL if w.aL else [self.F(0)])
            aR = ScalarVector(w.aR if w.aR else [self.F(0)])
            witness = ArithmeticCircuitWitness(aL, aR, w.commitments, w.scalars)

        return stmt, witness


__all__ = [
    "Circuit",
    "CurveSpec", "DlogParams", "OC_PARAMS", "C1_PARAMS", "C2_PARAMS",
    "Divisor", "PointWithDlog", "GeneratorTable", "ChallengePoint",
    "DiscreteLogChallenge", "ChallengedGenerator",
]
