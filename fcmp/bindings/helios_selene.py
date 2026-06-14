"""Helios/Selene Point operations implementation """

class WeierstrassCurve:
    """Short Weierstrass curve: y² = x³ + a·x + b (mod p)"""
    def __init__(self, a: int, b: int, prime: int):
        self.a = a % prime
        self.b = b % prime
        self.p = prime

    def __repr__(self):
        return f"WeierstrassCurve(a={hex(self.a)}, b={hex(self.b)}, p={hex(self.p)})"

class Point:
    """Elliptic curve point with full standard operations (affine coordinates)"""
    
    def __init__(self, curve: WeierstrassCurve, x: int | None = None, y: int | None = None):
        self.curve = curve
        if x is None or y is None:
            self.x = None   # Point at infinity
            self.y = None
        else:
            self.x = x % curve.p
            self.y = y % curve.p
            if not self.is_on_curve():
                raise ValueError(f"Point ({hex(self.x)}, {hex(self.y)}) is not on the curve")

    @classmethod
    def infinity(cls, curve: WeierstrassCurve):
        """Point at infinity """
        return cls(curve, None, None)

    def is_infinity(self) -> bool:
        return self.x is None

    def is_on_curve(self) -> bool:
        """Check y² ≡ x³ + a·x + b (mod p)"""
        if self.is_infinity():
            return True
        p = self.curve.p
        lhs = pow(self.y, 2, p)
        rhs = (pow(self.x, 3, p) + self.curve.a * self.x + self.curve.b) % p
        return lhs == rhs

    def __neg__(self):
        """-P"""
        if self.is_infinity():
            return self
        return Point(self.curve, self.x, (-self.y) % self.curve.p)

    def __add__(self, other):
        """P + Q (standard affine addition)"""
        if not isinstance(other, Point) or self.curve.p != other.curve.p:
            raise TypeError("Points must be on the same curve")

        p = self.curve.p
        a = self.curve.a

        if self.is_infinity():
            return other
        if other.is_infinity():
            return self

        # P + (-P) = 𝒪
        if self.x == other.x and (self.y + other.y) % p == 0:
            return Point.infinity(self.curve)

        # P == Q → use doubling
        if self.x == other.x and self.y == other.y:
            return self.double()

        # General case
        lam = ((other.y - self.y) * pow(other.x - self.x, p - 2, p)) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def double(self):
        if self.is_infinity():
            return self
        p = self.curve.p
        a = self.curve.a

        if self.y == 0:
            return Point.infinity(self.curve)

        lam = ((3 * self.x * self.x + a) * pow(2 * self.y, p - 2, p)) % p
        x3 = (lam * lam - 2 * self.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def __mul__(self, scalar: int):
        """Scalar multiplication k·P (double-and-add, left-to-right)"""
        if not isinstance(scalar, int):
            raise TypeError("Scalar must be integer")
        if scalar < 0:
            return (-scalar) * (-self)
        if scalar == 0 or self.is_infinity():
            return Point.infinity(self.curve)

        result = Point.infinity(self.curve)
        addend = self
        while scalar > 0:
            if scalar & 1:
                result = result + addend
            addend = addend.double()
            scalar >>= 1
        return result

    def __rmul__(self, scalar: int):
        return self * scalar

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        if self.is_infinity() and other.is_infinity():
            return True
        if self.is_infinity() or other.is_infinity():
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(∞)"
        return f"Point(x={hex(self.x)}, y={hex(self.y)})"

    def to_hex(self) -> str:
        """Return uncompressed hex (64 hex digits each)"""
        if self.is_infinity():
            return "infinity"
        return (f"x = {hex(self.x)[2:].zfill(64)}\n"
                f"y = {hex(self.y)[2:].zfill(64)}")
    