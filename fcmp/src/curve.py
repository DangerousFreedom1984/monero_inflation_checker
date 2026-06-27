"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Weierstrass curve arithmetic and compressed-point encoding for Helios/Selene.

Both curves: y² = x³ - 3x + B  (a = -3)

Point encoding (GroupEncoding, 32 bytes):
  bytes[0..31] = x-coordinate little-endian
  bit 7 of bytes[31] = is_odd(y)
  identity = all zeros  (x=0, sign=0)

Mirrors helioselene::HeliosPoint and SelenePoint in the Rust codebase.
"""

from field import HeliosField, SeleneField

# ---------------------------------------------------------------------------
# Curve constants (a = -3 for both)
# ---------------------------------------------------------------------------

# Helios: base field = HeliosField (p = 2^255-19), scalar field = SeleneField
# B from point.rs (big-endian hex interpreted as integer)
HELIOS_B = HeliosField(0x26BDEC0884FE05F20CB42071569FAB6432BE360D07DA8C5B460B82B980FD8C60)
HELIOS_GX = HeliosField(1)
HELIOS_GY = HeliosField(0x611DFFC62FE02C759E5AC10F40E009B8E3B147387068AAF810DBDF2D817C67BA)

# Selene: base field = SeleneField, scalar field = HeliosField
SELENE_B = SeleneField(0x38C40D10C226EF3BC597C2E1E25BC748E3401C3D031D14CA2265F309BA81EFE4)
SELENE_GX = SeleneField(1)
SELENE_GY = SeleneField(0x39098C0A54BD9D2781C7D734720D5CA639EE79DEEEFCD74517FCED93AD6635C0)


# ---------------------------------------------------------------------------
# Jacobian scalar multiplication (avoids inversion per step, ~50x faster)
# a = -3 for both curves → uses the specialized doubling formula.
# ---------------------------------------------------------------------------


def _jac_dbl(X, Y, Z, p, B):
    """Jacobian doubling for y² = x³ - 3x + B  (a = -3)."""
    if Z == 0:
        return (0, 1, 0)
    YY = Y * Y % p
    ZZ = Z * Z % p
    # alpha = 3*(X - ZZ)*(X + ZZ)  [exploiting a = -3]
    alpha = 3 * (X - ZZ) * (X + ZZ) % p
    beta = 4 * X * YY % p
    X3 = (alpha * alpha - 2 * beta) % p
    Y3 = (alpha * (beta - X3) - 8 * YY * YY) % p
    Z3 = 2 * Y * Z % p
    return (X3, Y3, Z3)


def _jac_add(X1, Y1, Z1, X2, Y2, Z2, p, B):
    """Jacobian addition (mixed if Z2=1)."""
    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)
    Z1Z1 = Z1 * Z1 % p
    Z2Z2 = Z2 * Z2 % p
    U1 = X1 * Z2Z2 % p
    U2 = X2 * Z1Z1 % p
    S1 = Y1 * Z2 * Z2Z2 % p
    S2 = Y2 * Z1 * Z1Z1 % p
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    if H == 0:
        if R == 0:
            return _jac_dbl(X1, Y1, Z1, p, B)
        return (0, 1, 0)
    HH = H * H % p
    HHH = H * HH % p
    X3 = (R * R - HHH - 2 * U1 * HH) % p
    Y3 = (R * (U1 * HH - X3) - S1 * HHH) % p
    Z3 = H * Z1 * Z2 % p
    return (X3, Y3, Z3)


def _jac_to_affine(X, Y, Z, p, field_cls, B):
    if Z == 0:
        return WPoint.identity(field_cls, B)
    Zinv = pow(Z, p - 2, p)
    Zinv2 = Zinv * Zinv % p
    x = field_cls(X * Zinv2 % p)
    y = field_cls(Y * Zinv2 * Zinv % p)
    return WPoint(field_cls, B, x, y)


def _scalar_mul_jacobian(pt: "WPoint", k: int) -> "WPoint":
    """Double-and-add in Jacobian coordinates; convert to affine once at end."""
    p = pt.field_cls.P
    B = pt.B
    fc = pt.field_cls
    Xb, Yb = pt.x.v, pt.y.v
    # result starts at infinity (Z=0), addend starts at pt (Z=1)
    rX, rY, rZ = 0, 1, 0
    aX, aY, aZ = Xb, Yb, 1
    while k:
        if k & 1:
            rX, rY, rZ = _jac_add(rX, rY, rZ, aX, aY, aZ, p, B)
        aX, aY, aZ = _jac_dbl(aX, aY, aZ, p, B)
        k >>= 1
    return _jac_to_affine(rX, rY, rZ, p, fc, B)


# ---------------------------------------------------------------------------
# Generic affine Weierstrass point (reused for both curves)
# ---------------------------------------------------------------------------


class WPoint:
    """Affine Weierstrass point over a field class.

    field_cls : HeliosField | SeleneField
    B         : the curve constant (HeliosField or SeleneField instance)
    x, y      : field elements, or both None for identity
    """

    __slots__ = ("field_cls", "B", "x", "y")

    def __init__(self, field_cls, B, x=None, y=None):
        self.field_cls = field_cls
        self.B = B
        self.x = x
        self.y = y

    @classmethod
    def identity(cls, field_cls, B):
        return cls(field_cls, B, None, None)

    def is_identity(self) -> bool:
        return self.x is None

    # curve equation: y² = x³ - 3x + B
    def _curve_eq(self, x):
        return x.square() * x - x.field_cls(3) * x + self.B

    def is_on_curve(self) -> bool:
        if self.is_identity():
            return True
        lhs = self.y.square()
        rhs = self._curve_eq(self.x)
        return lhs == rhs

    def __neg__(self):
        if self.is_identity():
            return WPoint(self.field_cls, self.B)
        return WPoint(self.field_cls, self.B, self.x, -self.y)

    def __add__(self, other: "WPoint") -> "WPoint":
        fc, B = self.field_cls, self.B
        if self.is_identity():
            return other
        if other.is_identity():
            return self

        if self.x == other.x:
            # P + (-P) = identity
            if self.y != other.y:
                return WPoint.identity(fc, B)
            # P == Q → doubling
            return self._double()

        lam = (other.y - self.y) * (other.x - self.x).inv()
        x3 = lam.square() - self.x - other.x
        y3 = lam * (self.x - x3) - self.y
        return WPoint(fc, B, x3, y3)

    def _double(self) -> "WPoint":
        fc, B = self.field_cls, self.B
        if self.is_identity() or self.y.is_zero():
            return WPoint.identity(fc, B)
        # lam = (3x² + a) / (2y),  a = -3  →  lam = (3x² - 3) / 2y = 3(x²-1) / 2y
        x2 = self.x.square()
        three = fc(3)
        lam = (three * x2 - three) * (fc(2) * self.y).inv()
        x3 = lam.square() - fc(2) * self.x
        y3 = lam * (self.x - x3) - self.y
        return WPoint(fc, B, x3, y3)

    def __mul__(self, scalar: int) -> "WPoint":
        if scalar < 0:
            return (-self) * (-scalar)
        if scalar == 0 or self.is_identity():
            return WPoint.identity(self.field_cls, self.B)
        return _scalar_mul_jacobian(self, scalar)

    def __rmul__(self, scalar: int) -> "WPoint":
        return self * scalar

    def __eq__(self, other) -> bool:
        if not isinstance(other, WPoint):
            return NotImplemented
        if self.is_identity() and other.is_identity():
            return True
        if self.is_identity() or other.is_identity():
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_identity():
            return "WPoint(identity)"
        return f"WPoint(x={self.x!r}, y={self.y!r})"


# ---------------------------------------------------------------------------
# Compressed-point encoding (matches GroupEncoding in point.rs)
# ---------------------------------------------------------------------------


def point_to_bytes(pt: WPoint) -> bytes:
    """Encode a point as 32 compressed bytes.

    Format: x LE (32 bytes), bit 7 of byte[31] = is_odd(y).
    Identity → all zeros.
    """
    if pt.is_identity():
        return bytes(32)
    x_bytes = bytearray(pt.x.to_bytes())
    sign = 1 if pt.y.is_odd() else 0
    x_bytes[31] |= sign << 7
    return bytes(x_bytes)


def _recover_y_helios(x: HeliosField):
    """Recover y for a Helios point (returns even y or None)."""
    rhs = x.square() * x - HeliosField(3) * x + HELIOS_B
    y = rhs.sqrt()
    if y is None:
        return None
    # Normalize to even (Field25519 sqrt doesn't always return even; enforce here)
    if y.is_odd():
        y = -y
    return y


def _recover_y_selene(x: SeleneField):
    """Recover y for a Selene point (returns even y or None)."""
    rhs = x.square() * x - SeleneField(3) * x + SELENE_B
    return rhs.sqrt()  # SeleneField.sqrt() already normalizes to even


def helios_from_bytes(b: bytes):
    """Decompress a 32-byte Helios point. Returns WPoint or None."""
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    sign = (b[31] >> 7) & 1
    raw = bytearray(b)
    raw[31] &= 0x7F
    x = HeliosField.from_bytes(bytes(raw))
    if x is None:
        return None
    if x.is_zero():
        if sign != 0:
            return None  # reject -0
        return WPoint.identity(HeliosField, HELIOS_B)
    y = _recover_y_helios(x)
    if y is None:
        return None
    if y.is_odd() != bool(sign):
        y = -y
    return WPoint(HeliosField, HELIOS_B, x, y)


def selene_from_bytes(b: bytes):
    """Decompress a 32-byte Selene point. Returns WPoint or None."""
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    sign = (b[31] >> 7) & 1
    raw = bytearray(b)
    raw[31] &= 0x7F
    x = SeleneField.from_bytes(bytes(raw))
    if x is None:
        return None
    if x.is_zero():
        if sign != 0:
            return None  # reject -0
        return WPoint.identity(SeleneField, SELENE_B)
    y = _recover_y_selene(x)
    if y is None:
        return None
    if y.is_odd() != bool(sign):
        y = -y
    return WPoint(SeleneField, SELENE_B, x, y)


# ---------------------------------------------------------------------------
# Outer-curve (Wei25519 / Ed25519) decompression
# ---------------------------------------------------------------------------
#
# Mirrors DivisorCurve::to_xy for EdwardsPoint in
# monero_oxide/crypto/divisors/src/lib.rs
# (E.2 of draft-ietf-lwig-curve-representations-02).
#
# Input:  32-byte Ed25519 compressed point
#         (y-coord LE, high bit = sign of x)
# Output: (HeliosField(wei_x), HeliosField(wei_y)) or None for identity/invalid

_OC_P = 2**255 - 19
_OC_D = (-121665 * pow(121666, _OC_P - 2, _OC_P)) % _OC_P
_OC_Y2X = (486662 * pow(3, _OC_P - 2, _OC_P)) % _OC_P
_OC_SQRT_M1 = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0
_OC_C = pow((_OC_P - 486664) % _OC_P, (_OC_P + 3) // 8, _OC_P) * _OC_SQRT_M1 % _OC_P
# Wei25519 curve parameters (y² = x³ + Ax + B over _OC_P), mirroring divisors.py
_WEI25519_A = 0x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144
_WEI25519_B = 0x7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864


def _wei25519_dbl_jac(X, Y, Z):
    """Jacobian doubling for y² = x³ + _WEI25519_A·x + _WEI25519_B (general a, dbl-2007-bl)."""
    p = _OC_P
    if Z == 0:
        return (0, 1, 0)
    ZZ = Z * Z % p
    W = (3 * X * X + _WEI25519_A * ZZ * ZZ) % p
    S = Y * Z % p
    B4 = 4 * X * Y * S % p
    H = (W * W - 2 * B4) % p
    X3 = 2 * H * S % p
    Y3 = (W * (B4 - H) - 8 * Y * Y * S * S) % p
    Z3 = 8 * S * S * S % p
    return (X3, Y3, Z3)


def _is_low_order_wei25519(wei_x: int, wei_y: int) -> bool:
    """True if the Wei25519 point is low-order (cofactor-8 torsion: 8*P = identity)."""
    X, Y, Z = wei_x, wei_y, 1
    for _ in range(3):
        X, Y, Z = _wei25519_dbl_jac(X, Y, Z)
    return Z == 0


def oc_from_bytes(b: bytes):
    """Decompress a 32-byte Ed25519 compressed point to Wei25519 (x,y) affine.

    Returns (HeliosField(x), HeliosField(y)) or None for the identity or an
    invalid encoding.  Used to decode O_tilde / I_tilde / R / C_tilde from
    FcmpInputCompressed 
    """
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    raw = bytearray(b)
    x_is_odd = (raw[31] >> 7) & 1
    raw[31] &= 0x7F
    y_ed = int.from_bytes(raw, "little")
    if y_ed >= _OC_P:
        return None
    y_sq = y_ed * y_ed % _OC_P
    numer = (y_sq - 1) % _OC_P
    denom = (_OC_D * y_sq + 1) % _OC_P
    x_sq = numer * pow(denom, _OC_P - 2, _OC_P) % _OC_P
    x_ed = pow(x_sq, (_OC_P + 3) // 8, _OC_P)
    if x_ed * x_ed % _OC_P != x_sq:
        x_ed = x_ed * _OC_SQRT_M1 % _OC_P
    if x_ed * x_ed % _OC_P != x_sq:
        return None
    if (x_ed % 2) != x_is_odd:
        x_ed = (_OC_P - x_ed) % _OC_P
    if x_ed == 0 and x_is_odd:
        return None
    one_minus_y = (1 - y_ed) % _OC_P
    if one_minus_y == 0:
        return None
    wei_x = ((1 + y_ed) * pow(one_minus_y, _OC_P - 2, _OC_P) + _OC_Y2X) % _OC_P
    denom_y = one_minus_y * x_ed % _OC_P
    if denom_y == 0:
        return None
    wei_y = _OC_C * (1 + y_ed) % _OC_P * pow(denom_y, _OC_P - 2, _OC_P) % _OC_P
    # Verify the recovered point satisfies y² = x³ + Ax + B over Wei25519.
    lhs = wei_y * wei_y % _OC_P
    rhs = (pow(wei_x, 3, _OC_P) + _WEI25519_A * wei_x + _WEI25519_B) % _OC_P
    if lhs != rhs:
        return None
    # Reject low-order points (cofactor-8 torsion: 8*P = identity means P ∉ prime-order subgroup).
    if _is_low_order_wei25519(wei_x, wei_y):
        return None
    return (HeliosField(wei_x), HeliosField(wei_y))


# ---------------------------------------------------------------------------
# Named generator points
# ---------------------------------------------------------------------------

HELIOS_G = WPoint(HeliosField, HELIOS_B, HELIOS_GX, HELIOS_GY)
SELENE_G = WPoint(SeleneField, SELENE_B, SELENE_GX, SELENE_GY)
