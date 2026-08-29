"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

gadgets.py - the FCMP++ circuit, one documented R1CS gadget per function.

Everything here is written in the language of r1cs.py: expressions are linear
combinations Lc over the wire vector z, and the only two statements a gadget can
make are

    cs.mul(a, b)        the row   <a, z> * <b, z> = <out, z>   (returns out)
    cs.assert_zero(e)   the row   <e, z> * 1 = 0

plus cs.mul_free_left / cs.mul_free_right for a row whose operand is a fresh
secret with no defining linear form (a slope, an inverse). 

The rows are byte-for-byte to those of the FCMP++ consensus circuit. A verifier
can rebuild this system from scratch and folds it in row order, so both the rows and
their order are wire format. What this decomposition adds over an inlined circuit
is one auditable unit per gadget.

Dependency graph (who calls whom):

    first_layer ── on_curve
                ├─ discrete_log ── on_curve
                │               ├─ divisor_challenge_eval   (x3)
                │               └─ inverse
                ├─ incomplete_add ── inequality ── inverse
                └─ tuple_member_of_list ── member_of_list
    additional_layer ── discrete_log, on_curve, incomplete_add, member_of_list
"""

from mic.fcmp.r1cs import Lc, R1CS, as_wire


class OnCurve:
    """The x, y wires of a point some gadget has confirmed is on the curve.

    Constraint-free: it only names the two wires. Returned by on_curve,
    incomplete_add and discrete_log, which is why it lives here rather than in
    circuit.py - nothing outside this module builds one.
    """

    def __init__(self, x, y):
        self._x = x
        self._y = y

    def x(self):
        return self._x

    def y(self):
        return self._y


# ===========================================================================
# Algebra gadgets
# ===========================================================================


def inverse(cs: "R1CS", value: "Lc", witness) -> "Lc":
    """Expose value^-1, which is satisfiable only if value != 0.

        row 1:   value * inv = out          (inv is a fresh witness)
        row 2:   out - 1 = 0

    Together: value * inv = 1. No assignment satisfies that when value = 0, so
    the gadget doubles as a non-zero proof.

    Cost: 1 mul, 2 linear.  Returns the inverse as an Lc.
    """
    with cs.record_block("inverse"):
        inv = None if witness is None else witness.inv()
        inv_lc, out = cs.mul_free_right(value, witness=inv)
        cs.assert_eq(out, cs.one())
        return inv_lc


def inequality(cs: "R1CS", a: "Lc", b: "Lc", witness) -> None:
    """Constrain a != b, by proving a - b is invertible.


    Cost: 1 mul, 2 linear (delegated to inverse).
    """
    with cs.record_block("inequality"):
        diff_witness = None if witness is None else witness[0] - witness[1]
        inverse(cs, a - b, diff_witness)


# ===========================================================================
# Elliptic-curve gadgets
# ===========================================================================


def on_curve(cs: "R1CS", curve, point) -> OnCurve:
    """Constrain (x, y) to satisfy the short-Weierstrass equation y^2 = x^3 + a*x + b.

        row:  x * x  = x2
        row: x2 * x  = x3
        row:  y * y  = y2
        row: y2 - x3 - a*x - b = 0

    Cost: 3 muls, 7 linear (each mul pins both its operands).
    """
    with cs.record_block("on_curve"):
        xw, yw = as_wire(point[0]), as_wire(point[1])
        x, y = cs.wire(xw), cs.wire(yw)

        x2 = cs.mul(x, x)
        x3 = cs.mul(x2, x)
        y2 = cs.mul(y, y)

        cs.assert_zero(y2 - x3 - x * curve.a - cs.constant(curve.b))
        return OnCurve(xw, yw)


def incomplete_add(cs: "R1CS", a, b, c) -> None:
    """Constrain a + b = c for a public point a and in-circuit b, c.

    The affine chord formula with a fresh slope wire lam:

        guard:  b.x != a.x                      (inequality, the excluded case)
        row:    lam * (b.x - a.x) = o1  ,  o1 - (b.y - a.y) = 0
        row:    lam * (c.x - a.x) = o2  ,  o2 + c.y + a.y  = 0
        row:    lam * lam            = o3  ,  o3 - b.x - c.x - a.x = 0

    The three lam rows pin lam and then pin c: given a, b and the slope, the last two
    determine c.x and c.y uniquely.

    Cost: 4 muls, 10 linear.  Returns OnCurve(c).
    """
    with cs.record_block("incomplete_add"):
        x0, y0 = a                      # the public point, as field elements
        bx, by = cs.wire(b.x()), cs.wire(b.y())
        cx, cy = cs.wire(c.x()), cs.wire(c.y())

        bx_val = cs.eval(bx)
        inequality(cs, bx, cs.constant(x0), None if bx_val is None else (bx_val, x0))

        slope_val = None
        if bx_val is not None:
            slope_val = (cs.eval(by) - y0) * (bx_val - x0).inv()

        # lam*(b.x - a.x) = b.y - a.y
        slope, o1 = cs.mul_free_left(bx - cs.constant(x0), witness=slope_val)
        cs.assert_eq(o1, by - cs.constant(y0))

        # lam*(c.x - a.x) = -c.y - a.y
        o2 = cs.mul(slope, cx - cs.constant(x0), witness=(slope_val, None))
        cs.assert_eq(o2, -cy - cs.constant(y0))

        # lam^2 = a.x + b.x + c.x
        o3 = cs.mul(slope, slope, witness=(slope_val, slope_val))
        cs.assert_eq(o3, bx + cx + cs.constant(x0))

        return OnCurve(c.x(), c.y())


# ===========================================================================
# Membership gadgets
# ===========================================================================


def member_of_list(cs: "R1CS", member: "Lc", items: list) -> None:
    """Constrain member in items via the vanishing product prod_i (item_i - member) = 0.

        row: (item0 - m) * (item1 - m) = p1
        row:          p1 * (item2 - m) = p2
        ...
        row: p_{k-2} = 0

    If member matched no entry every factor is non-zero, so is the product, and
    the closing row fails.

    Cost: k-1 muls for a list of length k, 2(k-1)+1 linear.
    """
    with cs.record_block("member_of_list"):
        assert len(items) > 0, "member_of_list: list must be non-empty"
        it = iter(items)
        product = next(it) - member
        for item in it:
            product = cs.mul(product, item - member)
        cs.assert_zero(product)


def tuple_member_of_list(cs: "R1CS", transcript, member, items: list,
                         field_cls: type = None) -> None:
    """Constrain membership of a tuple: (m0, ...) in items.

    Draws one Fiat-Shamir challenge g_j per coordinate and compresses every tuple to
    the single scalar sum_j g_j*v_j, then calls member_of_list on those. Because the
    g are drawn after the values are committed, two distinct tuples compress to the
    same scalar only with negligible probability.

    Cost: same as the inner member_of_list.
    """
    with cs.record_block("tuple_member_of_list"):
        F = field_cls if field_cls is not None else cs.F
        gammas = [transcript.challenge(F) for _ in member]

        def compress(tup):
            acc = Lc.zero()
            for gamma, v in zip(gammas, tup):
                acc = acc + cs.wire(v) * gamma
            return acc

        member_of_list(cs, compress(member), [compress(t) for t in items])


# ===========================================================================
# Divisor / discrete-log gadgets: the FCMP core
# ===========================================================================


def divisor_challenge_eval(cs: "R1CS", divisor, challenge) -> "Lc":
    """Evaluate the divisor's rational function n/d at one challenge point.

    n and d are linear forms over the committed divisor-coefficient wires (the
    prover's tape), built here from the challenge's precomputed powers. The
    division itself is one row:

        row:  d * quotient = n_claim         (quotient is a fresh witness)
        row:  n - n_claim = 0

    so quotient = n/d without ever dividing in-circuit.

    Cost: 1 mul, 2 linear.  Returns the quotient as an Lc.
    """
    with cs.record_block("divisor_challenge_eval"):
        F = cs.F

        # numerator, part 1: d/dy, scaled by p_0_n_0
        n1 = cs.wire(divisor.y) * challenge.p_0_n_0
        for j, var in enumerate(divisor.yx):
            n1 = n1 + cs.wire(var) * challenge.x_p_0_n_0[j]

        # numerator, part 2: d/dx
        n2 = cs.constant(F(1))
        n2 = n2 + cs.wire(divisor.yx[0]) * challenge.y
        for j in range(1, len(divisor.yx)):
            n2 = n2 + cs.wire(divisor.yx[j]) * (F(j + 1) * challenge.yx[j - 1])
        for i, xvar in enumerate(divisor.x_from_power_of_2):
            n2 = n2 + cs.wire(xvar) * (F(i + 2) * challenge.x[i])

        # denominator: the divisor evaluated at the challenge point
        d = cs.wire(divisor.y) * challenge.y
        for var, c_yx in zip(divisor.yx, challenge.yx):
            d = d + cs.wire(var) * c_yx
        for i, xvar in enumerate(divisor.x_from_power_of_2):
            d = d + cs.wire(xvar) * challenge.x[i + 1]
        d = d + cs.wire(divisor.zero) + cs.constant(challenge.x[0])

        n = (n1 + n2) * challenge.p_1_n
        d = d * challenge.p_1_d

        d_val = cs.eval(d)
        quotient_val = None if d_val is None else cs.eval(n) * d_val.inv()

        quotient, n_claim = cs.mul_free_right(d, witness=quotient_val)
        cs.assert_eq(n, n_claim)
        return quotient


def discrete_log_challenge(cs: "R1CS", transcript, curve, generator_tables: list):
    """Sample the Fiat-Shamir challenge structure a discrete_log is checked at.

    Draws two on-curve challenge points (rejection-sampled x, with parity bits from
    the transcript), forms c2 = -(c0 + c1) and the line through c0/c1, and batch-
    inverts the per-generator weights.

    Emits no rows: this is shared prover/verifier setup, not a constraint. It
    is here because the values it produces are what makes the in-circuit identity
    in discrete_log a random-point check.

    Cost: 0.  Returns (DiscreteLogChallenge, [ChallengedGenerator]).
    """
    # deferred: circuit.py imports this module at its top, so importing it back
    # at module level would close the loop.
    from mic.fcmp.circuit import (
        ChallengePoint, DiscreteLogChallenge, ChallengedGenerator, DlogParams, _batch_invert,
    )
    F = cs.F

    sign_bytes = transcript.challenge_bytes()
    sign_of_p0 = bool(sign_bytes[0] & 1)
    sign_of_p1 = bool((sign_bytes[0] >> 1) & 1)

    def sample_curve_point(odd_y):
        while True:
            cx = transcript.challenge(F)
            y2 = cx * cx * cx + curve.a * cx + curve.b
            cy = y2.sqrt()
            if cy is None:
                continue
            if cy.is_odd() != odd_y:
                cy = -cy
            return cx, cy

    c0x, c0y = sample_curve_point(sign_of_p0)
    c1x, c1y = sample_curve_point(sign_of_p1)

    def incomplete_add_affine(x1, y1, x2, y2):
        if x1 == x2:
            return None
        u = y2 - y1
        v = x2 - x1
        vv = v * v
        vvv = v * vv
        r = vv * x1
        aa = u * u - vvv - r - r
        x3 = v * aa
        y3 = u * (r - aa) - vvv * y1
        z3i = vvv.inv()
        return (x3 * z3i, y3 * z3i)

    res = incomplete_add_affine(c0x, c0y, c1x, c1y)
    if res is None:
        raise ValueError("challenge points share an x coordinate (negligible)")
    c2x, c2y = res
    c2y = -c2y

    slope = (c1y - c0y) * (c1x - c0x).inv()
    intercept = c0y - slope * c0x

    params = generator_tables[0] if generator_tables else None
    scalar_bits = params.scalar_bits if params else 1

    inversions = [c0y + c0y, c1y + c1y, c2y + c2y]
    for gt in generator_tables:
        for gx, gy in gt.table:
            inversions.append(intercept - (gy - slope * gx))
    for v in inversions:
        if v.is_zero():
            raise ValueError("inversion of zero (negligible)")
    inv_vals = _batch_invert(inversions)

    dlog_params = DlogParams(scalar_bits)
    c0 = ChallengePoint(curve, slope, c0x, c0y, inv_vals[0], dlog_params)
    c1 = ChallengePoint(curve, slope, c1x, c1y, inv_vals[1], dlog_params)
    c2 = ChallengePoint(curve, slope, c2x, c2y, inv_vals[2], dlog_params)

    gen_offset = 3
    challenged_generators = []
    for gt in generator_tables:
        weights = []
        for _ in range(gt.scalar_bits):
            weights.append(inv_vals[gen_offset])
            gen_offset += 1
        challenged_generators.append(ChallengedGenerator(weights))

    return DiscreteLogChallenge(c0, c1, c2, slope, intercept), challenged_generators


def discrete_log(cs: "R1CS", curve, point_with_dlog, challenge, challenged_gen) -> OnCurve:
    """Prove point = sum_i dlog_i * 2^i * G, the discrete-log-by-divisor gadget.

    Confirms the claimed point is on the curve, then asserts one identity:

        sum over j in {0,1,2} divisor_challenge_eval(D, c_j)
            = sum_i weight_i*dlog_i + (intercept + point.y + slope*point.x)^-1

    The left side is the logarithmic derivative of the divisor of the scalar-mul
    point multiset, read at the three challenge points. The right pairs the
    challenged generator weights against the committed dlog bits. The challenge is
    drawn after the commitments, so the identity holds only if the committed bits
    really do reconstruct the point.

    Cost: on_curve 3 + three divisor_challenge_eval 3 + inverse 1 = 7 muls.
    """
    with cs.record_block("discrete_log"):
        divisor = point_with_dlog.divisor
        point = on_curve(cs, curve, point_with_dlog.point)

        lhs = (
            divisor_challenge_eval(cs, divisor, challenge.c0)
            + divisor_challenge_eval(cs, divisor, challenge.c1)
            + divisor_challenge_eval(cs, divisor, challenge.c2)
        )

        rhs = Lc.zero()
        for bit, weight in zip(point_with_dlog.dlog, challenged_gen.weights):
            rhs = rhs + cs.wire(bit) * weight

        # the output line, interpolated at the claimed point
        out_line = (
            cs.constant(challenge.intercept)
            + cs.wire(point.y())
            + cs.wire(point.x()) * challenge.slope
        )
        rhs = rhs + inverse(cs, out_line, cs.eval(out_line))

        cs.assert_eq(lhs, rhs)
        return point


# ===========================================================================
# Layer assembly
# ===========================================================================


def additional_layer_discrete_log_challenge(cs: "R1CS", transcript, curve, H_table):
    """The discrete_log_challenge an interior layer needs: one generator, H."""
    challenge, cgens = discrete_log_challenge(cs, transcript, curve, [H_table])
    return challenge, cgens[0]


def first_layer(
    cs: "R1CS", transcript, curve, T_table, U_table, V_table, G_table,
    O_tilde, o_blind, O_vars, I_tilde, i_blind_u, I_vars, R, i_blind_v,
    i_blind_blind, C_tilde, c_blind, C_vars, branch: list,
) -> None:
    """The leaf layer for one input: recover O, I, R and C from their published
    rerandomized forms, and prove (O, I, C) is a leaf of the tree.

    For each of O, I and C: the point is on the curve, the blind is a known
    discrete log of its generator, and published = blind + point. The R relation
    ties the key-image blind to its own blind across two generators. Finally the
    recovered tuple must be one of the leaves in branch.

    The U and V discrete logs share their dlog wires deliberately
    (i_blind_u.dlog is i_blind_v.dlog): that aliasing is what forces one single
    i_blind scalar for both generators. If they were independent wires a prover
    could open i_blind to different scalars on U and V. The assertion below is
    the guard 

    Cost: 3 on_curve (9) + 5 discrete_log (35) + 4 incomplete_add (16)
        + 37 leaf membership = 97 muls, 216 linear.
    """
    with cs.record_block("first_layer"):
        challenge, cgens = discrete_log_challenge(
            cs, transcript, curve, [T_table, U_table, V_table, G_table]
        )
        challenged_T, challenged_U, challenged_V, challenged_G = cgens

        # O~ = O + o_blind*T
        O = on_curve(cs, curve, O_vars)
        o_blind_point = discrete_log(cs, curve, o_blind, challenge, challenged_T)
        incomplete_add(cs, O_tilde, o_blind_point, O)

        # Not an invariant, a soundness check: the U and V proofs must reference
        # the *same* wires, or a prover could open i_blind to a different scalar
        # on each generator. 
        if i_blind_u.dlog is not i_blind_v.dlog:
            raise ValueError(
                "first_layer: i_blind_v.dlog must be the identical object to "
                "i_blind_u.dlog, otherwise i_blind is not pinned across U and V"
            )

        # I~ = I + i_blind*U
        I = on_curve(cs, curve, I_vars)
        i_blind_u_point = discrete_log(cs, curve, i_blind_u, challenge, challenged_U)
        incomplete_add(cs, I_tilde, i_blind_u_point, I)

        # R = i_blind*V + i_blind_blind*T   (same i_blind scalar as above)
        i_blind_v_point = discrete_log(cs, curve, i_blind_v, challenge, challenged_V)
        i_blind_blind_point = discrete_log(cs, curve, i_blind_blind, challenge, challenged_T)
        incomplete_add(cs, R, i_blind_v_point, i_blind_blind_point)

        # C~ = C + c_blind*G
        C = on_curve(cs, curve, C_vars)
        c_blind_point = discrete_log(cs, curve, c_blind, challenge, challenged_G)
        incomplete_add(cs, C_tilde, c_blind_point, C)

        tuple_member_of_list(
            cs, transcript,
            [O.x(), O.y(), I.x(), I.y(), C.x(), C.y()],
            branch,
        )


def additional_layer(cs: "R1CS", curve, dlog_challenge_pair, blinded_hash, blind,
                     hash_vars, branch: list) -> None:
    """One interior tree layer: recover the node hash from its blinded form and
    prove its x-coordinate is among the parent branch's children.

    discrete_log(blind, H) + on_curve(hash) + incomplete_add +
    member_of_list(hash.x, branch). A node's x-coordinate lives in the scalar
    field of the other curve of the 2-cycle, which is why one layer's output is
    directly committable by the next.

    Cost: discrete_log 7 + on_curve 3 + incomplete_add 4 + (branch width - 1) + 1 mul
        = 15 + (branch width - 1) muls: 52 on C1 (width 38), 32 on C2 (width 18).
    """
    with cs.record_block("additional_layer"):
        challenge, challenged_gen = dlog_challenge_pair
        blind_point = discrete_log(cs, curve, blind, challenge, challenged_gen)
        hash_point = on_curve(cs, curve, hash_vars)
        incomplete_add(cs, blinded_hash, blind_point, hash_point)
        member_of_list(cs, cs.wire(hash_point.x()), [cs.wire(v) for v in branch])
