"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Full divisor computation pipeline for FCMP++:

  - Lagrange interpolation over the barycentric form
  - evaluation-domain arithmetic
  - ScalarDecomposition, new_divisor, scalar_mul_divisor

Every routine here is parameterized by a Curve (see curve.py) and does its field
arithmetic mod curve.p. Nothing defaults to a field. Three curves use it:
Wei25519 (the Weierstrass model of Ed25519) for the output
blinds and Selene/Helios for the branch blinds. Each curve in the cycle proves
its own scalar multiplications, so each needs divisors over its own base field.
"""

from mic.fcmp.curve import WEI25519, ProjectivePoint
from mic.fcmp.polynomial import Poly


# ---------------------------------------------------------------------------
# Batch modular inversion  (Montgomery's trick: 3(n-1) muls + 1 inv)
# ---------------------------------------------------------------------------


def batch_invert(vals, p):
    n = len(vals)
    if n == 0:
        return []
    prefix = [0] * n
    prefix[0] = int(vals[0]) % p
    for i in range(1, n):
        prefix[i] = prefix[i - 1] * int(vals[i]) % p
    inv_all = pow(prefix[-1], p - 2, p)
    result = [0] * n
    for i in range(n - 1, 0, -1):
        result[i] = inv_all * prefix[i - 1] % p
        inv_all = inv_all * int(vals[i]) % p
    result[0] = inv_all
    return result


def _batch_to_affine(points, p):
    """Convert projective points to (x, y) affine tuples via one batch inversion."""
    z_invs = batch_invert([pt.Z for pt in points], p)
    return [(pt.X * z_inv % p, pt.Y * z_inv % p) for pt, z_inv in zip(points, z_invs)]


# ---------------------------------------------------------------------------
# Lagrange interpolation
# ---------------------------------------------------------------------------


def _uni_mul_x_c(coeffs, c, p):
    """Multiply polynomial (leading first) by (x + c), return new list."""
    c = int(c) % p
    coeffs = list(coeffs) + [0]
    prior = coeffs[0]
    for i in range(1, len(coeffs)):
        this = coeffs[i]
        coeffs[i] = (this + prior * c) % p
        prior = this
    return coeffs


def _uni_div_x_c(coeffs, c, p):
    """Divide polynomial (leading first) by (x + c).  Returns (quotient, remainder)."""
    c = int(c) % p
    if not coeffs:
        return [], 0
    coeffs = list(coeffs)
    new_coeff = coeffs.pop(0)
    for i in range(len(coeffs)):
        this = coeffs[i]
        coeffs[i] = new_coeff
        new_coeff = (this - new_coeff * c) % p
    return coeffs, new_coeff


class Interpolator:
    """Precomputed Lagrange interpolator for x = 0, 1, ..., degree.

    The interpolate() method returns coefficients with leading term LAST.
    """

    def __init__(self, degree, p):
        self.degree = degree
        self.p = p
        self.domain_size = degree + 1
        self._lagrange_polys = self._precompute()

    def _inv_weights(self):
        """Compute inverted Lagrange weights 1/w_i for i in 0..n-1."""
        p = self.p
        n = self.domain_size
        # left[i] = prod(i - j for j in 0..i-1) = i!
        left = [1] * n
        acc = 1
        for i in range(1, n):
            acc = acc * i % p
            left[i] = acc
        # right[i] = prod(i - j for j in i+1..n-1) = (-1)^(n-1-i) * (n-1-i)!
        right = [1] * n
        acc = 1
        for i in range(n - 2, -1, -1):
            acc = acc * ((i - (n - 1)) % p) % p
            right[i] = acc
        weights = [left[i] * right[i] % p for i in range(n)]
        return batch_invert(weights, p)

    def _precompute(self):
        p = self.p
        n = self.domain_size
        # L(x) = (x-0)(x-1)...(x-(n-1)),  leading coeff first
        L = [1]
        for i in range(n):
            L = _uni_mul_x_c(L, (-i) % p, p)
        inv_w = self._inv_weights()
        polys = []
        for i in range(n):
            li, rem = _uni_div_x_c(L, (-i) % p, p)
            if rem != 0:
                raise ValueError(f"Lagrange remainder nonzero at i={i}")
            li = [c * inv_w[i] % p for c in li]
            polys.append(li)
        return polys

    def interpolate(self, evals):
        """Given n+1 evaluations at 0..degree, return poly with leading coeff LAST."""
        p = self.p
        n = self.domain_size
        poly = [0] * n
        for i in range(n):
            li = self._lagrange_polys[i]
            # li has leading coeff first, enumerate reversed gives (k, coeff of x^k)
            for k, c in enumerate(reversed(li)):
                poly[k] = (poly[k] + int(evals[i]) * c) % p
        return poly


# Keyed on (degree, p), not on the curve: Wei25519 and Helios share
# p = 2^255-19 but interpolate at different degrees (128 vs 130).
_INTERP_CACHE = {}


def get_interpolator(curve):
    """The scalar-mul-divisor interpolator for a curve."""
    key = (curve.divisor_interp_degree, curve.p)
    if key not in _INTERP_CACHE:
        _INTERP_CACHE[key] = Interpolator(*key)
    return _INTERP_CACHE[key]


# ---------------------------------------------------------------------------
# SmallDivisor
#   Represents: x_coeff*x + zero_coeff + y_coeff*y
# ---------------------------------------------------------------------------


class SmallDivisor:
    __slots__ = ("x_coeff", "zero_coeff", "y_coeff")

    def __init__(self, x_coeff, zero_coeff, y_coeff, p):
        self.x_coeff = int(x_coeff) % p
        self.zero_coeff = int(zero_coeff) % p
        self.y_coeff = int(y_coeff) % p


# ---------------------------------------------------------------------------
# Divisor  (evaluation-domain representation)
#   f(x, y) = A(x) - y * B(x), stored as evaluation vectors over the domain
# ---------------------------------------------------------------------------


class Divisor:
    __slots__ = ("a", "a_deg", "b", "b_deg")

    def __init__(self, a, a_deg, b, b_deg):
        self.a = list(a)
        self.a_deg = a_deg
        self.b = list(b)
        self.b_deg = b_deg

    # -- Construction ---------------------------------------------------

    @staticmethod
    def compute_modulus(curve, n):
        """Evaluations of x^3 + a*x + b at x = 0..n-1."""
        p, a_param, b_param = curve.p, curve.a, curve.b
        return [(i * i % p * i + a_param * i + b_param) % p for i in range(n)]

    @classmethod
    def from_small(cls, small, modulus, p):
        n = len(modulus)
        # A(x) = zero_coeff + x_coeff * x  (linear)
        a = [(small.zero_coeff + i * small.x_coeff) % p for i in range(n)]
        # B(x) = y_coeff  (constant)
        b = [small.y_coeff] * n
        return cls(a, 1, b, 0)

    # -- Multiplication mod (y^2 = x^3 + ax + b) ------------------------

    def mul_mod(self, other, modulus, p):
        """Product self * other in the evaluation domain.

        Uses: A_new = A1*A2 + mod*B1*B2,  B_new = A1*B2 + A2*B1
        (cross form: (A1+B1)(A2+B2) - A1A2 - B1B2 = cross term)
        """
        n = len(self.a)
        new_a_deg = max(self.a_deg + other.a_deg, 3 + self.b_deg + other.b_deg)
        new_b_deg = max(self.a_deg + other.b_deg, other.a_deg + self.b_deg)
        new_a = [0] * n
        new_b = [0] * n
        for i in range(n):
            A1, B1 = self.a[i], self.b[i]
            A2, B2 = other.a[i], other.b[i]
            a1a2 = A1 * A2 % p
            b1b2 = B1 * B2 % p
            cross = (A1 + B1) * (A2 + B2) % p
            new_b[i] = (cross - a1a2 - b1b2) % p
            new_a[i] = (a1a2 + b1b2 * modulus[i]) % p
        return Divisor(new_a, new_a_deg, new_b, new_b_deg)

    def mul_mod_small(self, small, modulus, p):
        """Product self * small_divisor in the evaluation domain.

        Same formula as mul_mod but A2(i) = zero_coeff + i*x_coeff, B2 = y_coeff.
        """
        n = len(self.a)
        new_a_deg = max(self.a_deg + 1, 3 + self.b_deg)
        new_b_deg = max(self.a_deg, 1 + self.b_deg)
        new_a = [0] * n
        new_b = [0] * n
        a2 = small.zero_coeff
        b2 = small.y_coeff
        for i in range(n):
            A1, B1 = self.a[i], self.b[i]
            a1a2 = A1 * a2 % p
            b1b2 = B1 * b2 % p
            cross = (A1 + B1) * (a2 + b2) % p
            new_b[i] = (cross - a1a2 - b1b2) % p
            new_a[i] = (a1a2 + b1b2 * modulus[i]) % p
            a2 = (a2 + small.x_coeff) % p
        return Divisor(new_a, new_a_deg, new_b, new_b_deg)

    # -- remove_diff  (divide by (x−x1)*(x−x2)) ------------------------

    def remove_diff(self, x1, x2, p):
        """Divide evaluations by (x_l − x1)*(x_r − x2).

        x1, x2: integer x-coordinates or None (when the point is the identity).
        When None, the corresponding factor is 1 for every evaluation point
        (using the sentinel x_val = -1 and inc = 0).
        Always subtracts 2 from tracked degrees regardless of None count.
        """
        n = len(self.a)
        inc_l = 1 if x1 is not None else 0
        inc_r = 1 if x2 is not None else 0
        xv1 = (int(x1) % p) if x1 is not None else (p - 1)  # -1 if None
        xv2 = (int(x2) % p) if x2 is not None else (p - 1)
        denom = []
        xl, xr = 0, 0
        for _ in range(n):
            denom.append((xl - xv1) * (xr - xv2) % p)
            xl = (xl + inc_l) % p
            xr = (xr + inc_r) % p
        inv_d = batch_invert(denom, p)
        new_a = [self.a[i] * inv_d[i] % p for i in range(n)]
        new_b = [self.b[i] * inv_d[i] % p for i in range(n)]
        # The denominator Evals always has degree 2, so always subtract 2
        return Divisor(new_a, self.a_deg - 2, new_b, self.b_deg - 2)

    @classmethod
    def merge(cls, d0, d1, small, denom, modulus, p):
        """d0 * d1 * small / denom  in the evaluation domain."""
        numerator = d0.mul_mod(d1, modulus, p).mul_mod_small(small, modulus, p)
        return numerator.remove_diff(denom[0], denom[1], p)

    def interpolate(self, interp):
        """Return (a_coeffs, b_coeffs) as lists of ints (leading coeff LAST)."""
        return interp.interpolate(self.a), interp.interpolate(self.b)


# ---------------------------------------------------------------------------
# Line computation
# ---------------------------------------------------------------------------


def _compute_line(ax, ay, a_is_id, bx, by, b_is_id, curve):
    """Compute SmallDivisor for the line (or degenerate case) through two points.

    Returns SmallDivisor representing:  x_coeff*x + zero_coeff + y_coeff*y
    """
    p = curve.p

    if a_is_id and b_is_id:
        return SmallDivisor(0, 1, 0, p)  # constant 1

    if a_is_id or b_is_id:
        x0 = bx if a_is_id else ax
        return SmallDivisor(1, -int(x0), 0, p)  # x - x0

    # Both are real points
    ax, ay, bx, by = int(ax) % p, int(ay) % p, int(bx) % p, int(by) % p

    if ax == bx:
        neg_ay = (-ay) % p
        if ay != 0 and by == neg_ay:
            # Additive inverses: vertical line x − ax
            return SmallDivisor(1, -ax, 0, p)
        # Same point: tangent line  slope = (3x² + a) / (2y)
        numer = (3 * ax % p * ax + curve.a) % p
        denom = 2 * ay % p
        if denom == 0:
            raise ValueError(
                f"degenerate tangent: 2-torsion point (y=0) at x={ax}; input must be in prime-order subgroup"
            )
        slope = numer * pow(denom, p - 2, p) % p
    else:
        dx = (bx - ax) % p
        dy = (by - ay) % p
        if dx == 0:
            raise ValueError(
                f"degenerate chord: x-coordinates equal ({ax}) but points not caught by equality check"
            )
        slope = dy * pow(dx, p - 2, p) % p

    intercept = (by - slope * bx) % p
    # line: y - slope*x - intercept  →  y_coeff=1, x_coeff=-slope, zero_coeff=-intercept
    return SmallDivisor(-slope, -intercept, 1, p)


# ---------------------------------------------------------------------------
# lines_and_denoms
# ---------------------------------------------------------------------------


def _lines_and_denoms(points, curve):
    """Build (SmallDivisor, (x1, x2)) for every pair in the merge tree.

    Level-0: pairs consecutive input points IN ORDER.
    Higher levels: pops from the END of the accumulated sums.
    The order this yields must match the order new_divisor's merge tree
    consumes it in.
    """
    n = len(points)
    all_pairs = []  # list of (ProjectivePoint, ProjectivePoint)

    # ----- Level 0: iterate forwards -----
    divs = []
    i = 0
    while i < n:
        a = points[i]
        b = points[i + 1] if i + 1 < n else ProjectivePoint.identity(curve)
        all_pairs.append((a, b))
        divs.append(b if a.is_identity() else (a if b.is_identity() else a + b))
        i += 2

    # ----- Higher levels: pop from end -----
    while len(divs) > 1:
        next_divs = []
        if len(divs) % 2 == 1:
            next_divs.append(divs.pop())  # carry the odd one out
        while divs:
            a = divs.pop()
            b = divs.pop()
            all_pairs.append((a, b))
            next_divs.append(a + b)
        divs = next_divs

    # ----- Batch convert all non-identity points to affine -----
    proj_list = []
    pair_slots = []  # (pair_index, 0_or_1, index_in_proj_list)
    for pi, (a, b) in enumerate(all_pairs):
        if not a.is_identity():
            pair_slots.append((pi, 0, len(proj_list)))
            proj_list.append(a)
        if not b.is_identity():
            pair_slots.append((pi, 1, len(proj_list)))
            proj_list.append(b)

    aff = _batch_to_affine(proj_list, curve.p) if proj_list else []

    # Fill in affine info: default = (0, 0, is_identity=True)
    pair_aff = [[(0, 0, True), (0, 0, True)] for _ in all_pairs]
    for pi, which, ki in pair_slots:
        pair_aff[pi][which] = (aff[ki][0], aff[ki][1], False)

    # ----- Compute lines and denoms -----
    result = []
    for pi, _ in enumerate(all_pairs):
        ax, ay, a_id = pair_aff[pi][0]
        bx, by, b_id = pair_aff[pi][1]
        line = _compute_line(ax, ay, a_id, bx, by, b_id, curve)
        x1 = None if a_id else ax
        x2 = None if b_id else bx
        result.append((line, (x1, x2)))
    return result


# ---------------------------------------------------------------------------
# divisor_to_poly
# ---------------------------------------------------------------------------


def _divisor_to_poly(div_obj, interp, field_cls):
    """Convert Divisor evaluation-domain representation to a Poly."""
    a_coeffs, b_coeffs = div_obj.interpolate(interp)
    # a_coeffs: [zero_coeff, x^1, x^2, ...]  (leading last)
    # b_coeffs: [y^1 coeff, yx^1 coeff, ...]  (same layout)
    zero_coeff = field_cls(a_coeffs[0])
    x_coefficients = [field_cls(c) for c in a_coeffs[1:]]
    y_coefficients = [field_cls(b_coeffs[0])]
    yx_coefficients = [[field_cls(c) for c in b_coeffs[1:]]]
    return Poly(zero_coeff, y_coefficients, yx_coefficients, x_coefficients)


def new_divisor(points, curve, interp=None):
    """Compute the divisor polynomial for a list of ProjectivePoints on curve.

    Returns a Poly or None on invalid input.
    """
    if interp is None:
        interp = get_interpolator(curve)

    n = len(points)
    if n < 2 or n % 2 != 0:
        return None
    for pt in points:
        if pt.is_identity():
            return None

    p = curve.p
    modulus = Divisor.compute_modulus(curve, interp.domain_size)
    lds = _lines_and_denoms(points, curve)
    ld_iter = iter(lds)

    # Create initial Divisors from level-0 pairs (first n//2 lines)
    divs = []
    for _ in range(n // 2):
        line, _denom = next(ld_iter)
        divs.append(Divisor.from_small(line, modulus, p))

    # Merge tree
    while len(divs) > 1:
        next_divs = []
        if len(divs) % 2 == 1:
            next_divs.append(divs.pop())
        while divs:
            a_div = divs.pop()
            b_div = divs.pop()
            line, denom = next(ld_iter)
            merged = Divisor.merge(a_div, b_div, line, denom, modulus, p)
            next_divs.append(merged)
        divs = next_divs

    # Convert to Poly
    poly = _divisor_to_poly(divs[0], interp, curve.field_cls)

    # Trim provably-zero trailing coefficients
    # yx[0] truncated to ceil(n/2) - 2
    trunc_yx = max(0, (n + 1) // 2 - 2)
    if poly.yx and len(poly.yx[0]) > trunc_yx:
        poly.yx[0] = poly.yx[0][:trunc_yx]
    # x truncated to n // 2
    trunc_x = n // 2
    if len(poly.x) > trunc_x:
        poly.x = poly.x[:trunc_x]

    return poly


# ---------------------------------------------------------------------------
# Scalar decomposition and scalar-mul divisors
# ---------------------------------------------------------------------------


class ScalarDecomposition:
    """Decompose a scalar s into coefficients d[i] such that:
    sum(d[i] * 2^i)  ==  s  (mod l)
    sum(d[i])        ==  NUM_BITS

    num_bits and the modulus come from the curve whose scalar field s lives in:
    Wei25519 by default, SELENE for a C1 blind, HELIOS for a C2 blind. Pass
    num_bits/modulus explicitly only to override them.
    """

    def __init__(self, scalar_int, curve=WEI25519, num_bits=None, modulus=None):
        if scalar_int == 0:
            raise ValueError("ScalarDecomposition requires a non-zero scalar")
        self.scalar = int(scalar_int)
        self.num_bits = curve.scalar_num_bits if num_bits is None else num_bits
        self.modulus = curve.scalar_modulus if modulus is None else modulus
        self.decomposition = _decompose(self.scalar, self.num_bits, self.modulus)

    def scalar_mul_divisor(self, T, interp=None):
        """Compute the normalized divisor Poly for scalar * T.

        T: ProjectivePoint (the generator). T.curve fixes the base field the
        divisor is computed over, and must be the same curve this scalar was
        decomposed against. The decomposition is only valid mod that curve's
        scalar field order.
        Returns a Poly with x_coefficients[0] == T.curve.field_cls(1).
        """
        if interp is None:
            interp = get_interpolator(T.curve)
        return _scalar_mul_divisor(self.scalar, self.decomposition, T, self.num_bits, interp)


def _decompose(scalar, num_bits, modulus):
    d = [(scalar >> i) & 1 for i in range(num_bits)]

    # A scalar below num_bits has too few set bits to ever reach sum(d) == num_bits
    # by expansion alone, so add a representation of the modulus: that changes
    # nothing modulo it, and supplies the weight the expansion loop needs.
    if scalar < num_bits:
        mod_d = [((modulus - 1) >> i) & 1 for i in range(num_bits)]
        mod_d[0] += 1  # bits of modulus itself
        d = [d[i] + mod_d[i] for i in range(num_bits)]

    # Both loops below rewrite d one step at a time, leaving sum(d[i] * 2^i)
    # untouched and moving sum(d) by exactly one: carrying (2 at i → 1 at i+1)
    # lowers it, expanding (1 at i → 2 at i-1) raises it. Which loop does the work
    # depends on the scalar. The other finds sum(d) already at num_bits and idles.
    log2_n = num_bits.bit_length()
    for _ in range(log2_n):
        done = sum(d) == num_bits
        for i in range(num_bits - 1):
            if not done and d[i] > 1:
                d[i] -= 2
                d[i + 1] += 1
                done = True

    for _ in range(num_bits):
        done = sum(d) == num_bits
        for i in range(num_bits - 1, 0, -1):
            if not done and d[i] != 0:
                d[i] -= 1
                d[i - 1] += 2
                done = True

    if sum(d) != num_bits:
        raise ValueError(
            f"scalar decomposition invariant violated: sum(d)={sum(d)}, expected {num_bits}. "
            f"scalar={scalar}, num_bits={num_bits}"
        )
    return d


def _scalar_mul_divisor(scalar, decomposition, T, num_bits, interp):
    """Build the divisor point array and call new_divisor.

    divisor_points[0]           = -(s * T)
    divisor_points[1..num_bits] = generators doubled appropriately
    """
    curve = T.curve
    neg_result = -(T * scalar)

    pts = [ProjectivePoint.identity(curve)] * (num_bits + 1)
    pts[0] = neg_result

    gen = ProjectivePoint(T.X, T.Y, T.Z, curve)
    write_above = 0
    for coeff in decomposition:
        for i in range(1, num_bits + 1):
            if i > write_above:
                pts[i] = ProjectivePoint(gen.X, gen.Y, gen.Z, curve)
        write_above += coeff
        gen = gen.double()

    poly = new_divisor(pts, curve, interp)
    if poly is None:
        raise RuntimeError("new_divisor returned None in scalar_mul_divisor")
    return poly.normalize_x_coefficient()
