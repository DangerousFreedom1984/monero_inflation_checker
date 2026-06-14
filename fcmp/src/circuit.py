# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments
# This project incorporates [`monero-oxide`](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

# circuit.py — FCMP++ arithmetic circuit gadgets.
#
# Translates (line-for-line):
#   circuit-abstraction/src/lib.rs         (Circuit, mul, eval, constrain_equal_to_zero)
#   circuit-abstraction/src/gadgets.rs     (equality, inverse, inequality)
#   ec-gadgets/src/lib.rs                  (on_curve, incomplete_add_fixed / incomplete_add_pub)
#   ec-gadgets/src/dlog.rs                 (GeneratorTable, ChallengePoint,
#                                           discrete_log_challenge, discrete_log)
#   gadgets/mod.rs                         (member_of_list)
#   gadgets/interactive.rs                 (tuple_member_of_list)
#   circuit.rs                             (first_layer, additional_layer_discrete_log_challenge,
#                                           additional_layer, statement)
#

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from gbp import (
    LinComb, ScalarVector,
    PedersenVectorCommitment, PedersenCommitment,
    ArithmeticCircuitStatement, ArithmeticCircuitWitness,
)
from tape import Variable as TapeVariable

# ---------------------------------------------------------------------------
# Variable helpers  (mirrors Variable enum in arithmetic_circuit_proof.rs)
# ---------------------------------------------------------------------------

def _aL(i):  return ("aL", i)
def _aR(i):  return ("aR", i)
def _aO(i):  return ("aO", i)
def _CG(ci, j): return ("CG", ci, j)

def _to_var(v):
    """Convert a tape Variable (or any gbp-style tuple) to a gbp CG tuple."""
    if isinstance(v, tuple):
        return v          # already ("aL"|"aR"|"aO"|"CG"|"V", ...)
    # tape.Variable(commitment, index)
    return _CG(v.commitment, v.index)

def _lc1(var, F):
    """LinComb with coefficient 1 for a single variable."""
    return LinComb.empty().term(F(1), _to_var(var))

# ---------------------------------------------------------------------------
# DlogParams  (mirrors DiscreteLogParameters trait bounds computed at compile time)
# ---------------------------------------------------------------------------

class DlogParams:
    """Computed DiscreteLogParameters for a given ScalarBits value."""
    def __init__(self, scalar_bits: int):
        self.scalar_bits = scalar_bits
        # XCoefficients = (scalar_bits + 1) // 2
        self.x_coefficients = (scalar_bits + 1) // 2
        # XCoefficientsMinusOne = x_coefficients - 1
        self.x_coefficients_minus_1 = self.x_coefficients - 1
        # YxCoefficients = (scalar_bits + 2) // 2 - 2
        self.yx_coefficients = (scalar_bits + 2) // 2 - 2

OC_PARAMS = DlogParams(253)   # Ed25519 group order: NUM_BITS = 253
C1_PARAMS = DlogParams(255)   # HelioseleneField:    NUM_BITS = 255
C2_PARAMS = DlogParams(255)   # HeliosField:         NUM_BITS = 255

# ---------------------------------------------------------------------------
# CurveSpec
# ---------------------------------------------------------------------------

class CurveSpec:
    """Short Weierstrass curve y^2 = x^3 + a*x + b."""
    def __init__(self, a, b):
        self.a = a
        self.b = b

# ---------------------------------------------------------------------------
# Divisor — variable references for a divisor polynomial
# ---------------------------------------------------------------------------

class Divisor:
    """
    Holds circuit Variable references for one divisor polynomial.
    Mirrors Divisor<Parameters> in ec-gadgets/src/dlog.rs.

    y                  : Variable — coefficient of y^1 x^0
    yx                 : list[Variable] — coefficients of y x^i (i=1..YxCoeff, skips i=0)
    x_from_power_of_2  : list[Variable] — coefficients of x^i (i=2..XCoeff, skips x^1)
    zero               : Variable — constant term (y^0 x^0)
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

# ---------------------------------------------------------------------------
# PointWithDlog — dlog + divisor + point variables
# ---------------------------------------------------------------------------

class PointWithDlog:
    """
    Holds circuit Variable references for a point with a discrete log proof.
    Mirrors PointWithDlog<Parameters> in ec-gadgets/src/dlog.rs.

    dlog    : list[Variable] — ScalarBits bit-decomposition variables
    divisor : Divisor
    point   : (Variable, Variable) — (x_var, y_var)
    """
    def __init__(self, dlog, divisor, point):
        # Convert in-place so list identity is preserved for shared-dlog cases 
        for i, v in enumerate(dlog):
            if not isinstance(v, tuple):
                dlog[i] = _to_var(v)
        self.dlog = dlog
        self.divisor = divisor
        self.point = (_to_var(point[0]), _to_var(point[1]))

# ---------------------------------------------------------------------------
# OnCurve — result of on_curve gadget
# ---------------------------------------------------------------------------

class OnCurve:
    """Wraps the x, y Variable references confirmed to be on a curve."""
    def __init__(self, x, y):
        self._x = x
        self._y = y

    def x(self): return self._x
    def y(self): return self._y

# ---------------------------------------------------------------------------
# GeneratorTable  (dlog.rs lines 110-149)
# ---------------------------------------------------------------------------

class GeneratorTable:
    """
    Precomputed table: table[i] = 2^i * generator.
    Uses mdbl-2007-bl Jacobian doubling, normalized to affine at each step.
    """
    def __init__(self, curve: CurveSpec, gx, gy, scalar_bits: int):
        self.scalar_bits = scalar_bits
        table = [(gx, gy)]
        for _ in range(1, scalar_bits):
            table.append(GeneratorTable._dbl(curve.a, *table[-1]))
        self.table = table

    @staticmethod
    def _dbl(a, x1, y1):
        """mdbl-2007-bl: affine output."""
        xx   = x1 * x1
        # w = a + 3*xx  (xx.double() in Rust = xx+xx)
        w    = a + xx + xx + xx
        y1y1 = y1 * y1
        r    = y1y1 + y1y1          # 2*y1^2
        # sss = (y1*r).double().double() = 4 * y1 * r
        yr   = y1 * r
        sss  = yr + yr
        sss  = sss + sss
        rr   = r * r
        b    = x1 + r
        b    = b * b - xx - rr      # 4*x1*y1^2
        h    = w * w - b - b        # w^2 - 2*b
        x3j  = (h + h) * y1        # 2*h*y1
        y3j  = w * (b - h) - rr - rr  # w*(b-h) - 2*rr
        z3   = sss                  # 8*y1^3
        z3i  = z3.inv()
        return (x3j * z3i, y3j * z3i)

# ---------------------------------------------------------------------------
# ChallengePoint  (dlog.rs lines 189-249)
# ---------------------------------------------------------------------------

class ChallengePoint:
    """
    Precomputed challenge-evaluation helpers for one point.
    """
    def __init__(self, curve: CurveSpec, slope, x, y, inv_two_y, dlog_params: DlogParams):
        x_count  = dlog_params.x_coefficients
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

        xx             = x * x
        three_x_sq_a   = xx + xx + xx + curve.a   # 3x^2 + a
        two_y          = y + y

        p_0_n_0 = three_x_sq_a * inv_two_y

        # x_p_0_n_0[i] = p_0_n_0 * x_pows[i],  length = yx_count  
        x_p_0_n_0 = [p_0_n_0 * x_pows[i] for i in range(yx_count)]

        # p_1_n = 2*y,  p_1_d = (-slope)*p_1_n + 3x^2+a 
        p_1_n = two_y
        p_1_d = (-slope) * p_1_n + three_x_sq_a

        self.y         = y
        self.yx        = yx
        self.x         = x_pows
        self.p_0_n_0   = p_0_n_0
        self.x_p_0_n_0 = x_p_0_n_0
        self.p_1_n     = p_1_n
        self.p_1_d     = p_1_d

# ---------------------------------------------------------------------------
# DiscreteLogChallenge / ChallengedGenerator
# ---------------------------------------------------------------------------

class DiscreteLogChallenge:
    """Three challenge points + line parameters."""
    def __init__(self, c0, c1, c2, slope, intercept):
        self.c0        = c0
        self.c1        = c1
        self.c2        = c2
        self.slope     = slope
        self.intercept = intercept

class ChallengedGenerator:
    """Inverted (intercept - (G_i.y - slope*G_i.x)) for each bit i."""
    def __init__(self, weights):
        self.weights = weights   # list[F], length = ScalarBits

# ---------------------------------------------------------------------------
# ProverData  (circuit-abstraction/src/lib.rs)
# ---------------------------------------------------------------------------

class ProverData:
    def __init__(self, C):
        """
        C : list of PedersenVectorCommitment (from the tape, with g_values + mask)
        V : list of PedersenCommitment (scalar commitments, unused in first/additional layer)
        """
        self.aL = []
        self.aR = []
        self.C  = list(C)
        self.V  = []

# ---------------------------------------------------------------------------
# Batch inversion helper
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Circuit  (circuit-abstraction/src/lib.rs + gadgets.rs + circuit.rs)
# ---------------------------------------------------------------------------

class Circuit:
    """
    Arithmetic circuit for Generalized Bulletproofs.

    field_cls   : HeliosField | HelioseleneField — the circuit's scalar field (C::F)
    prover_data : ProverData | None — None means verifier mode
    """

    def __init__(self, field_cls, prover_data=None):
        self.F            = field_cls
        self.muls_count   = 0
        self.constraints  = []           # list of LinComb (each = 0)
        self.prover_data  = prover_data

    @classmethod
    def prove(cls, field_cls, commitments):
        """Create a prover-mode circuit. commitments: list of PedersenVectorCommitment."""
        return cls(field_cls, ProverData(commitments))

    @classmethod
    def verify(cls, field_cls):
        """Create a verifier-mode circuit."""
        return cls(field_cls, None)

    def muls(self):
        return self.muls_count

    # ------------------------------------------------------------------
    # eval  (circuit-abstraction/src/lib.rs lines 116-138)
    # ------------------------------------------------------------------

    def eval(self, lincomb):
        """Evaluate a LinComb against the witness. Returns field element or None."""
        if self.prover_data is None:
            return None
        F  = self.F
        pd = self.prover_data
        res = lincomb.c if lincomb.c is not None else F(0)
        for i, w in lincomb.WL:
            res = res + pd.aL[i] * w
        for i, w in lincomb.WR:
            res = res + pd.aR[i] * w
        for i, w in lincomb.WO:
            res = res + pd.aL[i] * pd.aR[i] * w
        for ci, wrow in enumerate(lincomb.WCG):
            if ci < len(pd.C):
                gv = pd.C[ci].g_values
                for j, w in wrow:
                    if j < len(gv):
                        res = res + gv[j] * w
        for i, w in lincomb.WV:
            if i < len(pd.V):
                res = res + pd.V[i].value * w
        return res

    # ------------------------------------------------------------------
    # mul  (circuit-abstraction/src/lib.rs lines 145-171)
    # ------------------------------------------------------------------

    def mul(self, a=None, b=None, witness=None):
        """
        Add one multiplication gate.

        a, b     : Optional[LinComb] — if provided, constrain aL=a, aR=b respectively
        witness  : Optional[(F, F)]  — (aL_value, aR_value), required iff prover mode

        Returns (aL_var, aR_var, aO_var).
        """
        F = self.F
        i = self.muls_count
        l = _aL(i)
        r = _aR(i)
        o = _aO(i)
        self.muls_count += 1

        if self.prover_data is not None:
            assert witness is not None, "prover must supply witness for every mul"
            self.prover_data.aL.append(witness[0])
            self.prover_data.aR.append(witness[1])
        else:
            assert witness is None, "verifier must not supply witness"

        if a is not None:
            # Constraint: a - aL = 0
            self.constrain_equal_to_zero(a - _lc1(l, F))
        if b is not None:
            # Constraint: b - aR = 0
            self.constrain_equal_to_zero(b - _lc1(r, F))

        return l, r, o

    # ------------------------------------------------------------------
    # constrain_equal_to_zero / equality / inverse / inequality
    # (circuit-abstraction/src/gadgets.rs)
    # ------------------------------------------------------------------

    def constrain_equal_to_zero(self, lincomb):
        self.constraints.append(lincomb)

    def equality(self, a, b):
        """Constrain a == b (both LinCombs)."""
        self.constrain_equal_to_zero(a - b)

    def inverse(self, lincomb, witness):
        """
        Prove and constrain the inverse of a value.

        lincomb : Optional[LinComb] — constrain aL = lincomb
        witness : Optional[F]       — the value f (aR will be f.inv(), aO = 1)

        Returns (l, r) = (aL_var, aR_var).
        """
        F = self.F
        w = None if witness is None else (witness, witness.inv())
        l, r, o = self.mul(lincomb, None, w)
        # Constrain aO - 1 = 0
        self.constrain_equal_to_zero(_lc1(o, F).constant(-F(1)))
        return l, r

    def inequality(self, a, b, witness):
        """
        Constrain a != b.

        a, b    : LinCombs
        witness : Optional[(F, F)] — (a_val, b_val)
        """
        diff = a - b
        w = None if witness is None else (witness[0] - witness[1])
        self.inverse(diff, w)

    # ------------------------------------------------------------------
    # on_curve  (ec-gadgets/src/lib.rs lines 72-87)
    # ------------------------------------------------------------------

    def on_curve(self, curve: CurveSpec, point):
        """
        Constrain (x, y) to lie on `curve`.  Returns OnCurve{x, y}.

        point : (Variable, Variable) — (x_var, y_var)
        """
        F = self.F
        x, y = _to_var(point[0]), _to_var(point[1])

        x_lc   = _lc1(x, F)
        x_eval = self.eval(x_lc)

        # x2 = x * x   witness=(x, x)
        w_x2 = None if x_eval is None else (x_eval, x_eval)
        _, _, x2 = self.mul(_lc1(x, F), _lc1(x, F), w_x2)

        # x3 = x2 * x   witness=(x^2, x)  
        w_x3 = None if x_eval is None else (x_eval * x_eval, x_eval)
        _, _, x3 = self.mul(_lc1(x2, F), _lc1(x, F), w_x3)

        # expected_y2 = x3 + a*x + b
        expected_y2 = _lc1(x3, F).term(curve.a, x).constant(curve.b)

        y_lc   = _lc1(y, F)
        y_eval = self.eval(y_lc)

        # y2 = y * y   witness=(y, y)
        w_y2 = None if y_eval is None else (y_eval, y_eval)
        _, _, y2 = self.mul(_lc1(y, F), _lc1(y, F), w_y2)

        # Constraint: y2 == expected_y2
        self.equality(_lc1(y2, F), expected_y2)

        return OnCurve(x, y)

    # ------------------------------------------------------------------
    # incomplete_add_fixed  (ec-gadgets/src/lib.rs lines 89-131)
    # ------------------------------------------------------------------

    def incomplete_add_fixed(self, a, b: OnCurve, c: OnCurve):
        """
        Constrain a (public) + b (circuit) = c (circuit).

        a : (F, F) — public point coordinates
        b : OnCurve
        c : OnCurve
        Returns OnCurve{c.x, c.y} (the result is c itself).

        """
        F = self.F
        x0, y0 = a
        x1, y1 = b.x(), b.y()
        x2, y2 = c.x(), c.y()

        # Inequality check: b.x != x0 
        bx_lc   = _lc1(x1, F)
        bx_eval = self.eval(bx_lc)
        w_ineq  = None if bx_eval is None else (bx_eval, x0)
        self.inequality(bx_lc, LinComb.empty().constant(x0), w_ineq)

        # Slope witness
        slope_eval = None
        if bx_eval is not None:
            y1_eval    = self.eval(_lc1(y1, F))
            slope_eval = (y1_eval - y0) * (bx_eval - x0).inv()

        # Mul 1: slope * (x1 - x0) = y1 - y0
        # mul(None, Some(x1-x0), ...): slope=aL (free), x1-x0=aR (constrained) 
        x1_x0_lc   = _lc1(x1, F).constant(-x0)
        x1_x0_eval = self.eval(x1_x0_lc)
        w_m1        = None if slope_eval is None else (slope_eval, x1_x0_eval)
        slope_var, _, o1 = self.mul(None, x1_x0_lc, w_m1)
        # Constraint: o1 = y1 - y0
        self.equality(_lc1(o1, F), _lc1(y1, F).constant(-y0))

        # Mul 2: slope * (x2 - x0) = -y2 - y0
        x2_x0_lc   = _lc1(x2, F).constant(-x0)
        x2_x0_eval = self.eval(x2_x0_lc)
        w_m2        = None if slope_eval is None else (slope_eval, x2_x0_eval)
        _, _, o2 = self.mul(_lc1(slope_var, F), x2_x0_lc, w_m2)
        # Constraint: o2 = -y2 - y0
        self.equality(_lc1(o2, F), LinComb.empty().term(-F(1), y2).constant(-y0))

        # Mul 3: slope^2 = x0 + x1 + x2 
        w_m3 = None if slope_eval is None else (slope_eval, slope_eval)
        _, _, o3 = self.mul(_lc1(slope_var, F), _lc1(slope_var, F), w_m3)
        # Constraint: o3 = x1 + x2 + constant(x0)
        self.equality(_lc1(o3, F), _lc1(x1, F).term(F(1), x2).constant(x0))

        return OnCurve(x2, y2)

    # Convenience alias used in circuit.rs
    def incomplete_add_pub(self, a, b: OnCurve, c: OnCurve):
        return self.incomplete_add_fixed(a, b, c)

    # ------------------------------------------------------------------
    # member_of_list  (gadgets/mod.rs lines 14-34)
    # ------------------------------------------------------------------

    def member_of_list(self, member, list_lcs):
        """
        Constrain member ∈ list_lcs.

        member    : LinComb
        list_lcs  : list[LinComb]

        """
        assert len(list_lcs) > 0, "member_of_list: list must be non-empty"
        F = self.F

        it = iter(list_lcs)
        carry = next(it) - member

        for lc in it:
            nxt = lc - member
            carry_eval = self.eval(carry)
            nxt_eval   = self.eval(nxt)
            w = None if carry_eval is None else (carry_eval, nxt_eval)
            _, _, carry_var = self.mul(carry, nxt, w)
            carry = _lc1(carry_var, F)

        self.constrain_equal_to_zero(carry)

    # ------------------------------------------------------------------
    # tuple_member_of_list  (gadgets/interactive.rs lines 13-57)
    # ------------------------------------------------------------------

    def tuple_member_of_list(self, transcript, member_vars, list_tuples, field_cls=None):
        """
        Constrain (member_vars[0], ...) ∈ list_tuples using random challenges.

        member_vars  : list[Variable] — must all be CG 
        list_tuples  : list[list[Variable]] — same
        field_cls    : field class for challenge sampling (defaults to self.F)

        """
        F = field_cls if field_cls is not None else self.F

        # Validate: all must be CG  
        for v in member_vars:
            assert _to_var(v)[0] == "CG", \
                f"tuple_member_of_list: variable {v!r} is not CG"
        for tup in list_tuples:
            for v in tup:
                assert _to_var(v)[0] == "CG", \
                    f"tuple_member_of_list: variable {v!r} is not CG"

        # Sample one challenge per tuple element
        challenges = [transcript.challenge(F) for _ in member_vars]

        # Aggregate member into a single LinComb
        member_lc = LinComb.empty()
        for i, v in enumerate(member_vars):
            member_lc = member_lc + _lc1(v, F) * challenges[i]

        # Aggregate each list tuple
        list_lcs = []
        for tup in list_tuples:
            item = LinComb.empty()
            for i, v in enumerate(tup):
                item = item + _lc1(v, F) * challenges[i]
            list_lcs.append(item)

        self.member_of_list(member_lc, list_lcs)

    # ------------------------------------------------------------------
    # _divisor_challenge_eval  (ec-gadgets/src/dlog.rs lines 253-343)
    # ------------------------------------------------------------------

    def _divisor_challenge_eval(self, divisor: Divisor, challenge: ChallengePoint):
        """
        Evaluate the divisor at the challenge point, returning an output Variable.
        """
        F = self.F

        # --- p_0_n_1 : derivative by y, multiplied by p_0_n_0 ---
        p_0_n_1 = LinComb.empty().term(challenge.p_0_n_0, divisor.y)
        for j, var in enumerate(divisor.yx):
            p_0_n_1 = p_0_n_1 + LinComb.empty().term(challenge.x_p_0_n_0[j], var)

        # --- p_0_n_2 : derivative by x ---
        # Constant 1 (the normalized x^1 coefficient, diffs to 1)
        p_0_n_2 = LinComb.empty().constant(F(1))
        # New y coefficient: challenge.y * divisor.yx[0]
        p_0_n_2 = p_0_n_2 + LinComb.empty().term(challenge.y, divisor.yx[0])
        # yx for j >= 1: weight = (j+1) * challenge.yx[j-1] 
        for j in range(1, len(divisor.yx)):
            original_power = F(j + 1)
            this_weight    = original_power * challenge.yx[j - 1]
            p_0_n_2 = p_0_n_2 + LinComb.empty().term(this_weight, divisor.yx[j])
        # x coefficients: weight = (i+2) * challenge.x[i]  
        for i, xvar in enumerate(divisor.x_from_power_of_2):
            original_power = F(i + 2)
            this_weight    = original_power * challenge.x[i]
            p_0_n_2 = p_0_n_2 + LinComb.empty().term(this_weight, xvar)

        p_0_n = p_0_n_1 + p_0_n_2

        # --- p_0_d : evaluation of divisor at challenge ---
        p_0_d = LinComb.empty().term(challenge.y, divisor.y)
        for var, c_yx in zip(divisor.yx, challenge.yx):
            p_0_d = p_0_d + LinComb.empty().term(c_yx, var)
        for i, xvar in enumerate(divisor.x_from_power_of_2):
            # CRITICAL: uses challenge.x[i+1], not challenge.x[i] 
            p_0_d = p_0_d + LinComb.empty().term(challenge.x[i + 1], xvar)
        # 1 * divisor.zero + constant(challenge.x[0]) 
        last_term = LinComb.empty().term(F(1), divisor.zero).constant(challenge.x[0])
        p_0_d = p_0_d + last_term

        # p_n = p_0_n * p_1_n,  p_d = p_0_d * p_1_d
        p_n = p_0_n * challenge.p_1_n
        p_d = p_0_d * challenge.p_1_d

        # Circuit encodes n/d = o  as  d * o = n  
        # mul(p_d, None, witness=(p_d_val, p_n_val/p_d_val))
        # Returns (aL=p_d, aR=output, aO=n_claim)
        p_d_eval = self.eval(p_d)
        witness = None
        if p_d_eval is not None:
            p_n_eval = self.eval(p_n)
            witness  = (p_d_eval, p_n_eval * p_d_eval.inv())

        _l, o, n_claim = self.mul(p_d, None, witness)   
        # Constrain n_claim == p_n
        self.equality(p_n, _lc1(n_claim, F))

        return o   # aR = p_n / p_d

    # ------------------------------------------------------------------
    # discrete_log_challenge  (dlog.rs lines 409-527)
    # ------------------------------------------------------------------

    def discrete_log_challenge(self, transcript, curve: CurveSpec,
                               generator_tables):
        """
        Sample a DiscreteLogChallenge and ChallengedGenerators from the transcript.

        transcript       : ProverTranscript | VerifierTranscript
        curve            : CurveSpec (for the embedded curve)
        generator_tables : list[GeneratorTable]

        Returns (DiscreteLogChallenge, list[ChallengedGenerator]).
        """
        F = self.F

        # Sign bits for the two challenge points
        sign_bytes = transcript.challenge_bytes()
        sign_of_p0 = bool(sign_bytes[0] & 1)        # bit 0
        sign_of_p1 = bool((sign_bytes[0] >> 1) & 1) # bit 1

        def sample_curve_point(transcript, odd_y):
            """Loop until sqrt succeeds, then enforce y parity."""
            while True:
                cx = transcript.challenge(F)
                # y^2 = x^3 + a*x + b
                y2  = cx * cx * cx + curve.a * cx + curve.b
                cy  = y2.sqrt()
                if cy is None:
                    continue
                # Enforce requested parity
                if cy.is_odd() != odd_y:
                    cy = -cy
                return cx, cy

        c0x, c0y = sample_curve_point(transcript, sign_of_p0)
        c1x, c1y = sample_curve_point(transcript, sign_of_p1)

        # c2 = -(c0 + c1)  via mmadd-1998-cmo
        def incomplete_add_affine(x1, y1, x2, y2):
            if x1 == x2:
                return None
            u   = y2 - y1
            v   = x2 - x1
            vv  = v * v
            vvv = v * vv
            r   = vv * x1
            aa  = u * u - vvv - r - r
            x3  = v * aa
            y3  = u * (r - aa) - vvv * y1
            z3  = vvv
            z3i = z3.inv()
            return (x3 * z3i, y3 * z3i)

        res = incomplete_add_affine(c0x, c0y, c1x, c1y)
        assert res is not None, "challenge points share x coordinate (negligible probability)"
        c2x, c2y = res
        c2y = -c2y   # negate to get -(c0 + c1)

        # slope = (c1y - c0y) / (c1x - c0x)
        slope     = (c1y - c0y) * (c1x - c0x).inv()
        intercept = c0y - slope * c0x

        # Build batch-inversion inputs: [2*c0y, 2*c1y, 2*c2y, gen_terms...] 
        params = generator_tables[0] if generator_tables else None
        scalar_bits = params.scalar_bits if params else 1

        inversions = [c0y + c0y, c1y + c1y, c2y + c2y]
        for gt in generator_tables:
            for gx, gy in gt.table:
                # intercept - (G.y - slope * G.x) 
                inversions.append(intercept - (gy - slope * gx))

        # Validate — should all be non-zero
        for v in inversions:
            assert not v.is_zero(), "inversion of zero (negligible probability)"

        inv_vals = _batch_invert(inversions)

        inv_c0_2y = inv_vals[0]
        inv_c1_2y = inv_vals[1]
        inv_c2_2y = inv_vals[2]

        # Determine DlogParams from first table
        dlog_params = DlogParams(scalar_bits)

        c0 = ChallengePoint(curve, slope, c0x, c0y, inv_c0_2y, dlog_params)
        c1 = ChallengePoint(curve, slope, c1x, c1y, inv_c1_2y, dlog_params)
        c2 = ChallengePoint(curve, slope, c2x, c2y, inv_c2_2y, dlog_params)

        # Extract per-generator inverses 
        gen_offset = 3
        challenged_generators = []
        for gt in generator_tables:
            weights = []
            for i in range(gt.scalar_bits):
                weights.append(inv_vals[gen_offset])
                gen_offset += 1
            challenged_generators.append(ChallengedGenerator(weights))

        challenge = DiscreteLogChallenge(c0, c1, c2, slope, intercept)
        return challenge, challenged_generators

    # ------------------------------------------------------------------
    # discrete_log  (dlog.rs lines 529-589)
    # ------------------------------------------------------------------

    def discrete_log(self, curve: CurveSpec, point_with_dlog: PointWithDlog,
                     challenge: DiscreteLogChallenge,
                     challenged_gen: ChallengedGenerator) -> OnCurve:
        """
        Prove that point_with_dlog.point = sum(dlog[i] * table[i]).

        Returns OnCurve for the proven point.
        """
        F = self.F
        divisor  = point_with_dlog.divisor
        dlog     = point_with_dlog.dlog
        point_xy = point_with_dlog.point

        # Confirm the point is on curve
        on_curve_result = self.on_curve(curve, point_xy)

        # lhs = sum of divisor_challenge_eval at c0, c1, c2
        lhs = (
            _lc1(self._divisor_challenge_eval(divisor, challenge.c0), F) +
            _lc1(self._divisor_challenge_eval(divisor, challenge.c1), F) +
            _lc1(self._divisor_challenge_eval(divisor, challenge.c2), F)
        )

        # rhs = sum(weight[i] * dlog[i]) + inverse(output_interpolation)
        rhs = LinComb.empty()
        for bit_var, weight in zip(dlog, challenged_gen.weights):
            rhs = rhs + LinComb.empty().term(weight, bit_var)

        # Output point interpolation: intercept + point.y + slope * point.x 
        px_var = on_curve_result.x()
        py_var = on_curve_result.y()
        out_interp = (LinComb.empty()
                      .constant(challenge.intercept)
                      .term(F(1), py_var)
                      .term(challenge.slope, px_var))
        out_eval = self.eval(out_interp)
        _l, inv_var = self.inverse(out_interp, out_eval)
        rhs = rhs + _lc1(inv_var, F)

        self.equality(lhs, rhs)

        return on_curve_result

    # ------------------------------------------------------------------
    # first_layer  (circuit.rs lines 83-149)
    # ------------------------------------------------------------------

    def first_layer(self, transcript, curve: CurveSpec,
                    T_table, U_table, V_table, G_table,
                    O_tilde, o_blind: PointWithDlog, O_vars,
                    I_tilde, i_blind_u: PointWithDlog, I_vars,
                    R, i_blind_v: PointWithDlog, i_blind_blind: PointWithDlog,
                    C_tilde, c_blind: PointWithDlog, C_vars,
                    branch):
        """
        Prove the first layer of the FCMP.

        transcript : ProverTranscript | VerifierTranscript
        curve      : CurveSpec for the OC (Ed25519 Weierstrass) curve
        T/U/V/G_table : GeneratorTable for each generator
        O_tilde/I_tilde/R/C_tilde : (F, F) public input tuple points
        o_blind / i_blind_u / i_blind_v / i_blind_blind / c_blind : PointWithDlog
        O_vars / I_vars / C_vars : (Variable, Variable) — (x_var, y_var) from tape
        branch : list[list[Variable]] — leaf branch tuples (each 6-element)

        """
        # Sample challenge for all 4 generators: [T, U, V, G]  
        challenge, cgens = self.discrete_log_challenge(
            transcript, curve, [T_table, U_table, V_table, G_table])
        challenged_T, challenged_U, challenged_V, challenged_G = cgens

        # O: on_curve + dlog(o_blind, T) + O_tilde + o_blind = O
        O_curve = self.on_curve(curve, O_vars)
        o_blind_curve = self.discrete_log(curve, o_blind, challenge, challenged_T)
        self.incomplete_add_pub(O_tilde, o_blind_curve, O_curve)

        # Sanity: i_blind_v.dlog must share same Variable objects as i_blind_u.dlog
        assert i_blind_u.dlog is i_blind_v.dlog, \
            "first_layer: i_blind_v.dlog must be identical to i_blind_u.dlog"

        # I: on_curve + dlog(i_blind_u, U) + I_tilde + i_blind_u = I
        I_curve = self.on_curve(curve, I_vars)
        i_blind_u_curve = self.discrete_log(curve, i_blind_u, challenge, challenged_U)
        self.incomplete_add_pub(I_tilde, i_blind_u_curve, I_curve)

        # R: dlog(i_blind_v, V) + dlog(i_blind_blind, T) + R + v = blind_blind
        i_blind_v_curve = self.discrete_log(curve, i_blind_v, challenge, challenged_V)
        i_blind_blind_curve = self.discrete_log(
            curve, i_blind_blind, challenge, challenged_T)   # same T!  
        self.incomplete_add_pub(R, i_blind_v_curve, i_blind_blind_curve)

        # C: on_curve + dlog(c_blind, G) + C_tilde + c_blind = C
        C_curve = self.on_curve(curve, C_vars)
        c_blind_curve = self.discrete_log(curve, c_blind, challenge, challenged_G)
        self.incomplete_add_pub(C_tilde, c_blind_curve, C_curve)

        # Membership check: (O.x, O.y, I.x, I.y, C.x, C.y) ∈ branch
        self.tuple_member_of_list(
            transcript,
            [O_curve.x(), O_curve.y(), I_curve.x(), I_curve.y(),
             C_curve.x(), C_curve.y()],
            branch,
        )

    # ------------------------------------------------------------------
    # additional_layer_discrete_log_challenge  (circuit.rs lines 151-163)
    # ------------------------------------------------------------------

    def additional_layer_discrete_log_challenge(self, transcript,
                                                curve: CurveSpec, H_table):
        """
        Sample the shared challenge for all additional_layer calls on this circuit.

        Returns (DiscreteLogChallenge, ChallengedGenerator).
        """
        challenge, cgens = self.discrete_log_challenge(transcript, curve, [H_table])
        return challenge, cgens[0]

    # ------------------------------------------------------------------
    # additional_layer  (circuit.rs lines 165-186)
    # ------------------------------------------------------------------

    def additional_layer(self, curve: CurveSpec, dlog_challenge_pair,
                         blinded_hash, blind: PointWithDlog, hash_vars,
                         branch):
        """
        Prove one additional tree layer.

        curve               : CurveSpec for the embedded curve
        dlog_challenge_pair : (DiscreteLogChallenge, ChallengedGenerator) — shared
        blinded_hash        : (F, F) — public blinded hash point
        blind               : PointWithDlog
        hash_vars           : (Variable, Variable) — (x_var, y_var) for the unblinded hash
        branch              : list[Variable] — x-coordinates of the branch

        """
        challenge, challenged_gen = dlog_challenge_pair

        # dlog(blind, H)
        blind_curve = self.discrete_log(curve, blind, challenge, challenged_gen)

        # on_curve(hash)
        hash_curve = self.on_curve(curve, hash_vars)

        # blinded_hash + blind = hash  
        self.incomplete_add_pub(blinded_hash, blind_curve, hash_curve)

        # hash.x ∈ branch (x-coordinate only, NOT tuple) 
        branch_lcs = [_lc1(v, self.F) for v in branch]
        self.member_of_list(_lc1(hash_curve.x(), self.F), branch_lcs)

    # ------------------------------------------------------------------
    # statement  (circuit-abstraction/src/lib.rs lines 181-216)
    # ------------------------------------------------------------------

    def statement(self, generators, commitment_points):
        """
        Build the ArithmeticCircuitStatement (and optional witness).

        generators        : ProofGenerators
        commitment_points : list[WPoint] — committed curve points (from tape.commit)

        Returns (ArithmeticCircuitStatement, Optional[ArithmeticCircuitWitness]).
        """
        stmt = ArithmeticCircuitStatement(
            generators, self.constraints, commitment_points, [])

        witness = None
        if self.prover_data is not None:
            aL_vals = self.prover_data.aL if self.prover_data.aL else [self.F(0)]
            aR_vals = self.prover_data.aR if self.prover_data.aR else [self.F(0)]
            aL = ScalarVector(aL_vals)
            aR = ScalarVector(aR_vals)
            witness = ArithmeticCircuitWitness(aL, aR, self.prover_data.C, self.prover_data.V)

        return stmt, witness
