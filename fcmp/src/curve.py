# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments
# This project incorporates [`monero-oxide`](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

# Weierstrass curve arithmetic and compressed-point encoding for Helios/Selene.
#
# Both curves: y² = x³ - 3x + B  (a = -3)
#
# Point encoding (GroupEncoding, 32 bytes):
#   bytes[0..31] = x-coordinate little-endian
#   bit 7 of bytes[31] = is_odd(y)
#   identity = all zeros  (x=0, sign=0)
#
# Mirrors helioselene::HeliosPoint and SelenePoint in the Rust codebase.

from field import HeliosField, HelioseleneField

# ---------------------------------------------------------------------------
# Curve constants (a = -3 for both)
# ---------------------------------------------------------------------------

# Helios: base field = HeliosField (p = 2^255-19), scalar field = HelioseleneField
# B from point.rs (big-endian hex interpreted as integer)
HELIOS_B = HeliosField(
    0x26bdec0884fe05f20cb42071569fab6432be360d07da8c5b460b82b980fd8c60
)
HELIOS_GX = HeliosField(1)
HELIOS_GY = HeliosField(
    0x611dffc62fe02c759e5ac10f40e009b8e3b147387068aaf810dbdf2d817c67ba
)

# Selene: base field = HelioseleneField, scalar field = HeliosField
SELENE_B = HelioseleneField(
    0x38c40d10c226ef3bc597c2e1e25bc748e3401c3d031d14ca2265f309ba81efe4
)
SELENE_GX = HelioseleneField(1)
SELENE_GY = HelioseleneField(
    0x39098c0a54bd9d2781c7d734720d5ca639ee79deeefcd74517fced93ad6635c0
)


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

    field_cls : HeliosField | HelioseleneField
    B         : the curve constant (HeliosField or HelioseleneField instance)
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
            return f"WPoint(identity)"
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


def _recover_y_selene(x: HelioseleneField):
    """Recover y for a Selene point (returns even y or None)."""
    rhs = x.square() * x - HelioseleneField(3) * x + SELENE_B
    return rhs.sqrt()  # HelioseleneField.sqrt() already normalizes to even


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
    x = HelioseleneField.from_bytes(bytes(raw))
    if x is None:
        return None
    if x.is_zero():
        if sign != 0:
            return None  # reject -0
        return WPoint.identity(HelioseleneField, SELENE_B)
    y = _recover_y_selene(x)
    if y is None:
        return None
    if y.is_odd() != bool(sign):
        y = -y
    return WPoint(HelioseleneField, SELENE_B, x, y)


# ---------------------------------------------------------------------------
# Named generator points
# ---------------------------------------------------------------------------

HELIOS_G = WPoint(HeliosField, HELIOS_B, HELIOS_GX, HELIOS_GY)
SELENE_G = WPoint(HelioseleneField, SELENE_B, SELENE_GX, SELENE_GY)
