# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments
# This project incorporates [`monero-oxide`](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

# Full divisor computation pipeline for FCMP++.
# Translates:
#   - ec.rs           (Wei25519 projective arithmetic, dbl/add-1998-cmo-2)
#   - barycentric.rs  (Lagrange interpolation)
#   - divisor.rs      (evaluation-domain arithmetic)
#   - lib.rs          (ScalarDecomposition, new_divisor, scalar_mul_divisor)
#
# All field arithmetic uses HeliosField (p = 2^255 - 19), the base field of
# Wei25519 (the Weierstrass model of Ed25519 used for divisor computation).

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from field import HeliosField, HelioseleneField
from polynomial import Poly

# ---------------------------------------------------------------------------
# Global constants
# ---------------------------------------------------------------------------

P = HeliosField.P   # 2^255 - 19

# Wei25519 Weierstrass parameters  (from divisors/src/lib.rs ed25519 impl,
#   draft-ietf-lwig-curve-representations-02.pdf appendix E.3)
WEI25519_A = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
WEI25519_B = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864

# Ed25519 scalar field order l = 2^252 + 27742317777372353535851937790883648493
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_NUM_BITS = 253   # PrimeField::NUM_BITS for dalek_ff_group::Scalar

# Interpolator degree for scalar-mul divisors (from DivisorCurve impl for Ed25519)
INTERPOLATOR_DEGREE = 128

# Interpolator degree for Selene / Helios (interpolator_for_scalar_mul returns 130)
INTERPOLATOR_DEGREE_C1C2 = 130

# a=-3 as integers in each curve's base field
SELENE_A = HelioseleneField.P - 3   # -3 mod HelioseleneField.P
HELIOS_A = HeliosField.P - 3        # -3 mod HeliosField.P  (same as HeliosField.P - 3)


# ---------------------------------------------------------------------------
# Batch modular inversion  (Montgomery's trick: 3(n-1) muls + 1 inv)
# ---------------------------------------------------------------------------

def batch_invert(vals, p=P):
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


# ---------------------------------------------------------------------------
# Wei25519 projective arithmetic  (from ec.rs)
#   Identity: (X=0, Y=1, Z=0)
#   Coordinates are plain Python integers mod P.
# ---------------------------------------------------------------------------

class Wei25519Point:
    __slots__ = ("X", "Y", "Z")

    def __init__(self, X, Y, Z):
        self.X = int(X) % P
        self.Y = int(Y) % P
        self.Z = int(Z) % P

    @classmethod
    def identity(cls):
        return cls(0, 1, 0)

    @classmethod
    def from_affine(cls, x, y):
        return cls(int(x) % P, int(y) % P, 1)

    def is_identity(self):
        return self.Z == 0

    def to_affine(self):
        z_inv = pow(self.Z, P - 2, P)
        return (self.X * z_inv % P, self.Y * z_inv % P)

    def __neg__(self):
        return Wei25519Point(self.X, (-self.Y) % P, self.Z)

    def __eq__(self, other):
        lx = self.X * other.Z % P
        rx = other.X * self.Z % P
        ly = self.Y * other.Z % P
        ry = other.Y * self.Z % P
        return lx == rx and ly == ry

    # dbl-1998-cmo-2  (uses WEI25519_A)
    def double(self):
        if self.is_identity():
            return Wei25519Point.identity()
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X1X1 = X1 * X1 % P
        w  = (WEI25519_A * Z1 % P * Z1 + X1X1 + X1X1 + X1X1) % P
        s   = Y1 * Z1 % P
        ss  = s * s % P
        sss = s * ss % P
        R   = Y1 * s % P
        B   = X1 * R % P
        B4  = B * 4 % P
        h   = (w * w - B4 * 2) % P
        X3  = h * s * 2 % P
        Y3  = (w * (B4 - h) - R * R * 8) % P
        Z3  = sss * 8 % P
        return Wei25519Point(X3, Y3, Z3)

    # add-1998-cmo-2  (no a term in addition formula)
    def __add__(self, p2):
        if self.is_identity():
            return Wei25519Point(p2.X, p2.Y, p2.Z)
        if p2.is_identity():
            return Wei25519Point(self.X, self.Y, self.Z)
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = p2.X, p2.Y, p2.Z
        Y1Z2 = Y1 * Z2 % P
        X1Z2 = X1 * Z2 % P
        Z1Z2 = Z1 * Z2 % P
        u   = (Y2 * Z1 - Y1Z2) % P
        uu  = u * u % P
        v   = (X2 * Z1 - X1Z2) % P
        vv  = v * v % P
        vvv = v * vv % P
        R   = vv * X1Z2 % P
        A   = (uu * Z1Z2 - vvv - 2 * R) % P
        X3  = v * A % P
        Y3  = (u * (R - A) - vvv * Y1Z2) % P
        Z3  = vvv * Z1Z2 % P
        # Edge cases
        same_x = X1 * Z2 % P == X2 * Z1 % P
        if same_x:
            if Y1 * Z2 % P == Y2 * Z1 % P:
                return self.double()
            return Wei25519Point.identity()
        return Wei25519Point(X3, Y3, Z3)

    def __mul__(self, k):
        k = int(k)
        if k == 0 or self.is_identity():
            return Wei25519Point.identity()
        if k < 0:
            return (-self).__mul__(-k)
        result = Wei25519Point.identity()
        base = Wei25519Point(self.X, self.Y, self.Z)
        while k:
            if k & 1:
                result = result + base
            base = base.double()
            k >>= 1
        return result

    def __rmul__(self, k):
        return self.__mul__(k)

    def __repr__(self):
        if self.is_identity():
            return "Wei25519Point(identity)"
        x, y = self.to_affine()
        return f"Wei25519Point(x={x:064x}, y={y:064x})"


def _batch_to_affine(points):
    """Convert a list of Wei25519Points to (x, y) affine tuples via one batch inversion."""
    zs = [p.Z for p in points]
    z_invs = batch_invert(zs)
    return [(p.X * z_inv % P, p.Y * z_inv % P) for p, z_inv in zip(points, z_invs)]


# ---------------------------------------------------------------------------
# Lagrange interpolation  (from barycentric.rs)
# ---------------------------------------------------------------------------

def _uni_mul_x_c(coeffs, c, p=P):
    """Multiply polynomial (leading first) by (x + c), return new list."""
    c = int(c) % p
    coeffs = list(coeffs) + [0]
    prior = coeffs[0]
    for i in range(1, len(coeffs)):
        this = coeffs[i]
        coeffs[i] = (this + prior * c) % p
        prior = this
    return coeffs


def _uni_div_x_c(coeffs, c, p=P):
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

    Matches barycentric.rs Interpolator::new(degree).
    The interpolate() method returns coefficients with leading term LAST.
    """

    def __init__(self, degree, p=P):
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
            assert rem == 0, f"Lagrange remainder nonzero at i={i}"
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
            # li has leading coeff first; enumerate reversed gives (k, coeff of x^k)
            for k, c in enumerate(reversed(li)):
                poly[k] = (poly[k] + int(evals[i]) * c) % p
        return poly


_INTERP_CACHE = {}

def get_interpolator(degree=INTERPOLATOR_DEGREE, p=P):
    key = (degree, p)
    if key not in _INTERP_CACHE:
        _INTERP_CACHE[key] = Interpolator(degree, p)
    return _INTERP_CACHE[key]


# ---------------------------------------------------------------------------
# SmallDivisor  (from divisor.rs)
#   Represents: x_coeff*x + zero_coeff + y_coeff*y
# ---------------------------------------------------------------------------

class SmallDivisor:
    __slots__ = ("x_coeff", "zero_coeff", "y_coeff")

    def __init__(self, x_coeff, zero_coeff, y_coeff, p=None):
        _p = p if p is not None else P
        self.x_coeff   = int(x_coeff)  % _p
        self.zero_coeff = int(zero_coeff) % _p
        self.y_coeff   = int(y_coeff)  % _p


# ---------------------------------------------------------------------------
# Divisor  (evaluation-domain representation, from divisor.rs)
#   f(x, y) = A(x) - y * B(x), stored as evaluation vectors at x = 0..128
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
    def compute_modulus(a_param, b_param, n, p=P):
        """Evaluations of x^3 + a*x + b at x = 0..n-1."""
        return [(i * i % p * i + a_param * i + b_param) % p for i in range(n)]

    @classmethod
    def from_small(cls, small, modulus, p=P):
        n = len(modulus)
        # A(x) = zero_coeff + x_coeff * x  (linear)
        a = [(small.zero_coeff + i * small.x_coeff) % p for i in range(n)]
        # B(x) = y_coeff  (constant)
        b = [small.y_coeff] * n
        return cls(a, 1, b, 0)

    # -- Multiplication mod (y^2 = x^3 + ax + b) ------------------------

    def mul_mod(self, other, modulus, p=P):
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
            a1a2  = A1 * A2 % p
            b1b2  = B1 * B2 % p
            cross = (A1 + B1) * (A2 + B2) % p
            new_b[i] = (cross - a1a2 - b1b2) % p
            new_a[i] = (a1a2 + b1b2 * modulus[i]) % p
        return Divisor(new_a, new_a_deg, new_b, new_b_deg)

    def mul_mod_small(self, small, modulus, p=P):
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
            a1a2  = A1 * a2 % p
            b1b2  = B1 * b2 % p
            cross = (A1 + B1) * (a2 + b2) % p
            new_b[i] = (cross - a1a2 - b1b2) % p
            new_a[i] = (a1a2 + b1b2 * modulus[i]) % p
            a2 = (a2 + small.x_coeff) % p
        return Divisor(new_a, new_a_deg, new_b, new_b_deg)

    # -- remove_diff  (divide by (x−x1)*(x−x2)) ------------------------

    def remove_diff(self, x1, x2, p=P):
        """Divide evaluations by (x_l − x1)*(x_r − x2).

        x1, x2: integer x-coordinates or None (when the point is the identity).
        When None, the corresponding factor is 1 for every evaluation point
        (using the sentinel x_val = −1 and inc = 0, same as Rust).
        Always subtracts 2 from tracked degrees regardless of None count.
        """
        n = len(self.a)
        inc_l = 1 if x1 is not None else 0
        inc_r = 1 if x2 is not None else 0
        xv1   = (int(x1) % p) if x1 is not None else (p - 1)  # -1 if None
        xv2   = (int(x2) % p) if x2 is not None else (p - 1)
        denom = []
        xl, xr = 0, 0
        for _ in range(n):
            denom.append((xl - xv1) * (xr - xv2) % p)
            xl = (xl + inc_l) % p
            xr = (xr + inc_r) % p
        inv_d = batch_invert(denom, p)
        new_a = [self.a[i] * inv_d[i] % p for i in range(n)]
        new_b = [self.b[i] * inv_d[i] % p for i in range(n)]
        # Rust always assigns degree:2 to the denominator Evals → always subtract 2
        return Divisor(new_a, self.a_deg - 2, new_b, self.b_deg - 2)

    @classmethod
    def merge(cls, d0, d1, small, denom, modulus, p=P):
        """d0 * d1 * small / denom  in the evaluation domain."""
        numerator = d0.mul_mod(d1, modulus, p).mul_mod_small(small, modulus, p)
        return numerator.remove_diff(denom[0], denom[1], p)

    def interpolate(self, interp):
        """Return (a_coeffs, b_coeffs) as lists of ints (leading coeff LAST)."""
        return interp.interpolate(self.a), interp.interpolate(self.b)


# ---------------------------------------------------------------------------
# Line computation  (from lib.rs finish_line / slopes_and_intercepts)
# ---------------------------------------------------------------------------

def _compute_line(ax, ay, a_is_id, bx, by, b_is_id):
    """Compute SmallDivisor for the line (or degenerate case) through two points.

    Returns SmallDivisor representing:  x_coeff*x + zero_coeff + y_coeff*y
    """
    if a_is_id and b_is_id:
        return SmallDivisor(0, 1, 0)                  # constant 1

    if a_is_id or b_is_id:
        x0 = bx if a_is_id else ax
        return SmallDivisor(1, (-int(x0)) % P, 0)     # x - x0

    # Both are real points
    ax, ay, bx, by = int(ax) % P, int(ay) % P, int(bx) % P, int(by) % P

    if ax == bx:
        neg_ay = (-ay) % P
        if ay != 0 and by == neg_ay:
            # Additive inverses: vertical line x − ax
            return SmallDivisor(1, (-ax) % P, 0)
        # Same point: tangent line  slope = (3x² + A) / (2y)
        numer = (3 * ax % P * ax + WEI25519_A) % P
        denom = 2 * ay % P
        slope = numer * pow(denom, P - 2, P) % P
    else:
        dx    = (bx - ax) % P
        dy    = (by - ay) % P
        slope = dy * pow(dx, P - 2, P) % P

    intercept = (by - slope * bx) % P
    # line: y - slope*x - intercept  →  y_coeff=1, x_coeff=-slope, zero_coeff=-intercept
    return SmallDivisor((-slope) % P, (-intercept) % P, 1)


# ---------------------------------------------------------------------------
# lines_and_denoms  (matches the pair-ordering of lib.rs lines_and_denoms)
# ---------------------------------------------------------------------------

def _lines_and_denoms(points):
    """Build (SmallDivisor, (x1, x2)) for every pair in the merge tree.

    Level-0: pairs consecutive input points IN ORDER (matches Rust iter.next()).
    Higher levels: pops from the END of the accumulated sums (matches Rust pop()).
    """
    n = len(points)
    all_pairs = []   # list of (Wei25519Point, Wei25519Point)

    # ----- Level 0: iterate forwards -----
    divs = []
    i = 0
    while i < n:
        a = points[i]
        b = points[i + 1] if i + 1 < n else Wei25519Point.identity()
        all_pairs.append((a, b))
        divs.append(b if a.is_identity() else (a if b.is_identity() else a + b))
        i += 2

    # ----- Higher levels: pop from end -----
    while len(divs) > 1:
        next_divs = []
        if len(divs) % 2 == 1:
            next_divs.append(divs.pop())   # carry the odd one out
        while divs:
            a = divs.pop()
            b = divs.pop()
            all_pairs.append((a, b))
            next_divs.append(a + b)
        divs = next_divs

    # ----- Batch convert all non-identity points to affine -----
    proj_list  = []
    pair_slots = []   # (pair_index, 0_or_1, index_in_proj_list)
    for pi, (a, b) in enumerate(all_pairs):
        if not a.is_identity():
            pair_slots.append((pi, 0, len(proj_list)))
            proj_list.append(a)
        if not b.is_identity():
            pair_slots.append((pi, 1, len(proj_list)))
            proj_list.append(b)

    aff = _batch_to_affine(proj_list) if proj_list else []

    # Fill in affine info: default = (0, 0, is_identity=True)
    pair_aff = [[(0, 0, True), (0, 0, True)] for _ in all_pairs]
    for (pi, which, ki) in pair_slots:
        pair_aff[pi][which] = (aff[ki][0], aff[ki][1], False)

    # ----- Compute lines and denoms -----
    result = []
    for pi, _ in enumerate(all_pairs):
        (ax, ay, a_id) = pair_aff[pi][0]
        (bx, by, b_id) = pair_aff[pi][1]
        line = _compute_line(ax, ay, a_id, bx, by, b_id)
        x1 = None if a_id else ax
        x2 = None if b_id else bx
        result.append((line, (x1, x2)))
    return result


# ---------------------------------------------------------------------------
# divisor_to_poly  (from lib.rs divisor_to_poly)
# ---------------------------------------------------------------------------

def _divisor_to_poly(div_obj, interp):
    """Convert Divisor evaluation-domain representation to a Poly."""
    a_coeffs, b_coeffs = div_obj.interpolate(interp)
    # a_coeffs: [zero_coeff, x^1, x^2, ..., x^128]  (leading last)
    # b_coeffs: [y^1 coeff, yx^1 coeff, ..., yx^127]  (same layout)
    zero_coeff     = HeliosField(a_coeffs[0])
    x_coefficients = [HeliosField(c) for c in a_coeffs[1:]]
    y_coefficients = [HeliosField(b_coeffs[0])]
    yx_coefficients = [[HeliosField(c) for c in b_coeffs[1:]]]
    return Poly(zero_coeff, y_coefficients, yx_coefficients, x_coefficients)


# ---------------------------------------------------------------------------
# new_divisor  (from lib.rs new_divisor)
# ---------------------------------------------------------------------------

def new_divisor(points, interp=None):
    """Compute the divisor polynomial for a list of Wei25519Points.

    Returns a Poly or None on invalid input.
    points must be a list of Wei25519Point objects.
    """
    if interp is None:
        interp = get_interpolator()

    n = len(points)
    if n < 2 or n % 2 != 0:
        return None
    for p in points:
        if p.is_identity():
            return None

    modulus = Divisor.compute_modulus(WEI25519_A, WEI25519_B, interp.domain_size)
    lds = _lines_and_denoms(points)
    ld_iter = iter(lds)

    # Create initial Divisors from level-0 pairs (first n//2 lines)
    divs = []
    for _ in range(n // 2):
        line, _denom = next(ld_iter)
        divs.append(Divisor.from_small(line, modulus))

    # Merge tree
    while len(divs) > 1:
        next_divs = []
        if len(divs) % 2 == 1:
            next_divs.append(divs.pop())
        while divs:
            a_div = divs.pop()
            b_div = divs.pop()
            line, denom = next(ld_iter)
            merged = Divisor.merge(a_div, b_div, line, denom, modulus)
            next_divs.append(merged)
        divs = next_divs

    # Convert to Poly
    poly = _divisor_to_poly(divs[0], interp)

    # Trim provably-zero trailing coefficients  (mirrors lib.rs trim())
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
# Generic projective point for a-arbitrary Weierstrass curves (Selene/Helios)
# Uses dbl-1998-cmo-2 with a generic `a` parameter.
# ---------------------------------------------------------------------------

class GenericProjectivePoint:
    """Projective point on y² = x³ + a·x + b with coordinates mod p."""
    __slots__ = ("X", "Y", "Z", "p", "a")

    def __init__(self, X, Y, Z, p, a):
        self.X = int(X) % p
        self.Y = int(Y) % p
        self.Z = int(Z) % p
        self.p = p
        self.a = int(a) % p

    @classmethod
    def identity(cls, p, a):
        return cls(0, 1, 0, p, a)

    @classmethod
    def from_affine(cls, x, y, p, a):
        return cls(int(x) % p, int(y) % p, 1, p, a)

    def is_identity(self):
        return self.Z == 0

    def to_affine(self):
        z_inv = pow(self.Z, self.p - 2, self.p)
        return (self.X * z_inv % self.p, self.Y * z_inv % self.p)

    def __neg__(self):
        return GenericProjectivePoint(self.X, (-self.Y) % self.p, self.Z, self.p, self.a)

    def double(self):
        if self.is_identity():
            return GenericProjectivePoint.identity(self.p, self.a)
        p = self.p
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X1X1 = X1 * X1 % p
        # dbl-1998-cmo-2: w = a*Z1² + 3*X1²
        w   = (self.a * Z1 % p * Z1 + X1X1 + X1X1 + X1X1) % p
        s   = Y1 * Z1 % p
        ss  = s * s % p
        sss = s * ss % p
        R   = Y1 * s % p
        B_  = X1 * R % p
        B4  = B_ * 4 % p
        h   = (w * w - B4 * 2) % p
        X3  = h * s * 2 % p
        Y3  = (w * (B4 - h) - R * R * 8) % p
        Z3  = sss * 8 % p
        return GenericProjectivePoint(X3, Y3, Z3, p, self.a)

    def __add__(self, q):
        if self.is_identity():
            return GenericProjectivePoint(q.X, q.Y, q.Z, self.p, self.a)
        if q.is_identity():
            return GenericProjectivePoint(self.X, self.Y, self.Z, self.p, self.a)
        p = self.p
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = q.X, q.Y, q.Z
        Y1Z2 = Y1 * Z2 % p
        X1Z2 = X1 * Z2 % p
        Z1Z2 = Z1 * Z2 % p
        u    = (Y2 * Z1 - Y1Z2) % p
        uu   = u * u % p
        v    = (X2 * Z1 - X1Z2) % p
        vv   = v * v % p
        vvv  = v * vv % p
        R    = vv * X1Z2 % p
        A    = (uu * Z1Z2 - vvv - 2 * R) % p
        X3   = v * A % p
        Y3   = (u * (R - A) - vvv * Y1Z2) % p
        Z3   = vvv * Z1Z2 % p
        if X1 * Z2 % p == X2 * Z1 % p:
            if Y1 * Z2 % p == Y2 * Z1 % p:
                return self.double()
            return GenericProjectivePoint.identity(p, self.a)
        return GenericProjectivePoint(X3, Y3, Z3, p, self.a)

    def __mul__(self, k):
        k = int(k)
        if k == 0 or self.is_identity():
            return GenericProjectivePoint.identity(self.p, self.a)
        if k < 0:
            return (-self).__mul__(-k)
        result = GenericProjectivePoint.identity(self.p, self.a)
        base = GenericProjectivePoint(self.X, self.Y, self.Z, self.p, self.a)
        while k:
            if k & 1:
                result = result + base
            base = base.double()
            k >>= 1
        return result

    def __rmul__(self, k):
        return self.__mul__(k)


# ---------------------------------------------------------------------------
# Generic helpers for Selene/Helios divisor computation
# ---------------------------------------------------------------------------

def _compute_line_generic(ax, ay, a_id, bx, by, b_id, curve_a, p):
    """Like _compute_line but for a generic curve (curve_a, p)."""
    if a_id and b_id:
        return SmallDivisor(0, 1, 0, p)
    if a_id or b_id:
        x0 = bx if a_id else ax
        return SmallDivisor(1, (-int(x0)) % p, 0, p)
    ax, ay, bx, by = int(ax) % p, int(ay) % p, int(bx) % p, int(by) % p
    if ax == bx:
        neg_ay = (-ay) % p
        if ay != 0 and by == neg_ay:
            return SmallDivisor(1, (-ax) % p, 0, p)
        numer = (3 * ax % p * ax + curve_a) % p
        denom2 = 2 * ay % p
        slope = numer * pow(denom2, p - 2, p) % p
    else:
        dx = (bx - ax) % p
        dy = (by - ay) % p
        slope = dy * pow(dx, p - 2, p) % p
    intercept = (by - slope * bx) % p
    return SmallDivisor((-slope) % p, (-intercept) % p, 1, p)


def _lines_and_denoms_generic(points, curve_a, p):
    """Like _lines_and_denoms but for GenericProjectivePoint lists."""
    n = len(points)
    all_pairs = []
    divs = []
    i = 0
    while i < n:
        a = points[i]
        b = points[i + 1] if i + 1 < n else GenericProjectivePoint.identity(p, curve_a)
        all_pairs.append((a, b))
        divs.append(b if a.is_identity() else (a if b.is_identity() else a + b))
        i += 2
    while len(divs) > 1:
        next_divs = []
        if len(divs) % 2 == 1:
            next_divs.append(divs.pop())
        while divs:
            a = divs.pop()
            b = divs.pop()
            all_pairs.append((a, b))
            next_divs.append(a + b)
        divs = next_divs
    proj_list = []
    pair_slots = []
    for pi, (a, b) in enumerate(all_pairs):
        if not a.is_identity():
            pair_slots.append((pi, 0, len(proj_list)))
            proj_list.append(a)
        if not b.is_identity():
            pair_slots.append((pi, 1, len(proj_list)))
            proj_list.append(b)
    if proj_list:
        zs = [pt.Z for pt in proj_list]
        z_invs = batch_invert(zs, p)
        aff = [(pt.X * z_inv % p, pt.Y * z_inv % p) for pt, z_inv in zip(proj_list, z_invs)]
    else:
        aff = []
    pair_aff = [[(0, 0, True), (0, 0, True)] for _ in all_pairs]
    for (pi, which, ki) in pair_slots:
        pair_aff[pi][which] = (aff[ki][0], aff[ki][1], False)
    result = []
    for pi, _ in enumerate(all_pairs):
        (ax, ay, a_id) = pair_aff[pi][0]
        (bx, by, b_id) = pair_aff[pi][1]
        line = _compute_line_generic(ax, ay, a_id, bx, by, b_id, curve_a, p)
        x1 = None if a_id else ax
        x2 = None if b_id else bx
        result.append((line, (x1, x2)))
    return result


def _divisor_to_poly_generic(div_obj, interp, field_cls):
    """Like _divisor_to_poly but constructs coefficients as field_cls elements."""
    a_coeffs, b_coeffs = div_obj.interpolate(interp)
    zero_coeff      = field_cls(a_coeffs[0])
    x_coefficients  = [field_cls(c) for c in a_coeffs[1:]]
    y_coefficients  = [field_cls(b_coeffs[0])]
    yx_coefficients = [[field_cls(c) for c in b_coeffs[1:]]]
    return Poly(zero_coeff, y_coefficients, yx_coefficients, x_coefficients)


def _new_divisor_generic(points, interp, p, curve_a, curve_b, field_cls):
    """Like new_divisor but for GenericProjectivePoints with curve params (p, curve_a, curve_b)."""
    n = len(points)
    if n < 2 or n % 2 != 0:
        return None
    for pt in points:
        if pt.is_identity():
            return None
    modulus = Divisor.compute_modulus(curve_a, curve_b, interp.domain_size, p)
    lds = _lines_and_denoms_generic(points, curve_a, p)
    ld_iter = iter(lds)
    divs = []
    for _ in range(n // 2):
        line, _denom = next(ld_iter)
        divs.append(Divisor.from_small(line, modulus, p))
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
    poly = _divisor_to_poly_generic(divs[0], interp, field_cls)
    trunc_yx = max(0, (n + 1) // 2 - 2)
    if poly.yx and len(poly.yx[0]) > trunc_yx:
        poly.yx[0] = poly.yx[0][:trunc_yx]
    trunc_x = n // 2
    if len(poly.x) > trunc_x:
        poly.x = poly.x[:trunc_x]
    return poly


def _scalar_mul_divisor_generic(scalar, decomposition, T, num_bits, interp, p, curve_a, curve_b, field_cls):
    """Like _scalar_mul_divisor but for a generic curve."""
    neg_result = -(T * scalar)
    pts = [GenericProjectivePoint.identity(p, curve_a)] * (num_bits + 1)
    pts[0] = neg_result
    gen = GenericProjectivePoint(T.X, T.Y, T.Z, p, curve_a)
    write_above = 0
    for coeff in decomposition:
        for i in range(1, num_bits + 1):
            if i > write_above:
                pts[i] = GenericProjectivePoint(gen.X, gen.Y, gen.Z, p, curve_a)
        write_above += coeff
        gen = gen.double()
    poly = _new_divisor_generic(pts, interp, p, curve_a, curve_b, field_cls)
    if poly is None:
        raise RuntimeError("_new_divisor_generic returned None in _scalar_mul_divisor_generic")
    return poly.normalize_x_coefficient()


# ---------------------------------------------------------------------------
# ScalarDecomposition  (from lib.rs ScalarDecomposition::new)
# ---------------------------------------------------------------------------

class ScalarDecomposition:
    """Decompose a scalar s into coefficients d[i] such that:
         sum(d[i] * 2^i)  ==  s  (mod l)
         sum(d[i])        ==  NUM_BITS
    """

    def __init__(self, scalar_int, num_bits=ED25519_NUM_BITS, modulus=ED25519_L):
        if scalar_int == 0:
            raise ValueError("ScalarDecomposition requires a non-zero scalar")
        self.scalar = int(scalar_int)
        self.num_bits = num_bits
        self.decomposition = _decompose(int(scalar_int), num_bits, modulus)

    def scalar_mul_divisor(self, T, interp=None):
        """Compute the normalized divisor Poly for scalar * T.

        T: Wei25519Point (the generator in projective form).
        Returns Poly with x_coefficients[0] == HeliosField(1).
        """
        if interp is None:
            interp = get_interpolator()
        return _scalar_mul_divisor(self.scalar, self.decomposition, T, self.num_bits, interp)

    def scalar_mul_divisor_selene(self, A):
        """Compute divisor for scalar * A on Selene (C1).

        A: WPoint on Selene (field_cls=HelioseleneField).
        Returns Poly with x_coefficients[0] == HelioseleneField(1).
        ScalarDecomposition must have been built with num_bits=255 and modulus=HeliosField.P.
        """
        from curve import SELENE_B
        p = HelioseleneField.P
        curve_a = SELENE_A          # = p - 3
        curve_b = int(SELENE_B.v)
        interp = get_interpolator(INTERPOLATOR_DEGREE_C1C2, p)
        T = GenericProjectivePoint.from_affine(int(A.x.v), int(A.y.v), p, curve_a)
        return _scalar_mul_divisor_generic(
            self.scalar, self.decomposition, T, self.num_bits, interp,
            p, curve_a, curve_b, HelioseleneField,
        )

    def scalar_mul_divisor_helios(self, A):
        """Compute divisor for scalar * A on Helios (C2).

        A: WPoint on Helios (field_cls=HeliosField).
        Returns Poly with x_coefficients[0] == HeliosField(1).
        ScalarDecomposition must have been built with num_bits=255 and modulus=HelioseleneField.P.
        """
        from curve import HELIOS_B
        p = HeliosField.P
        curve_a = HELIOS_A          # = p - 3
        curve_b = int(HELIOS_B.v)
        interp = get_interpolator(INTERPOLATOR_DEGREE_C1C2)
        T = GenericProjectivePoint.from_affine(int(A.x.v), int(A.y.v), p, curve_a)
        return _scalar_mul_divisor_generic(
            self.scalar, self.decomposition, T, self.num_bits, interp,
            p, curve_a, curve_b, HeliosField,
        )


# ---------------------------------------------------------------------------
# _decompose  (ScalarDecomposition::new algorithm)
# ---------------------------------------------------------------------------

def _decompose(scalar, num_bits, modulus):
    # Step 1: LE bits of scalar (num_bits of them)
    d = [(scalar >> i) & 1 for i in range(num_bits)]

    # Step 2: If scalar < num_bits, add the field modulus representation
    if scalar < num_bits:
        mod_d = [((modulus - 1) >> i) & 1 for i in range(num_bits)]
        mod_d[0] += 1   # bits of `modulus` itself
        d = [d[i] + mod_d[i] for i in range(num_bits)]

    # Step 3: Phase 1 — reduce coefficients > 1 by carrying upward
    log2_n = num_bits.bit_length()
    for _ in range(log2_n):
        done = (sum(d) == num_bits)
        for i in range(num_bits - 1):
            if not done and d[i] > 1:
                d[i]     -= 2
                d[i + 1] += 1
                done = True

    # Step 4: Phase 2 — expand by pulling from highest non-zero
    for _ in range(num_bits):
        done = (sum(d) == num_bits)
        for i in range(num_bits - 1, 0, -1):
            if not done and d[i] != 0:
                d[i]     -= 1
                d[i - 1] += 2
                done = True

    return d


# ---------------------------------------------------------------------------
# _scalar_mul_divisor  (ScalarDecomposition::scalar_mul_divisor)
# ---------------------------------------------------------------------------

def _scalar_mul_divisor(scalar, decomposition, T, num_bits, interp):
    """Build the 254-point divisor array and call new_divisor.

    divisor_points[0]           = -(s * T)
    divisor_points[1..num_bits] = generators doubled appropriately
    """
    neg_result = (T * scalar).__neg__()

    pts = [Wei25519Point.identity()] * (num_bits + 1)
    pts[0] = neg_result

    gen = Wei25519Point(T.X, T.Y, T.Z)
    write_above = 0
    for coeff in decomposition:
        for i in range(1, num_bits + 1):
            if i > write_above:
                pts[i] = Wei25519Point(gen.X, gen.Y, gen.Z)
        write_above += coeff
        gen = gen.double()

    poly = new_divisor(pts, interp)
    if poly is None:
        raise RuntimeError("new_divisor returned None in scalar_mul_divisor")
    return poly.normalize_x_coefficient()
