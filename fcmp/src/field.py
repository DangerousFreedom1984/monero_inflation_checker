"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Finite field arithmetic for Helios/Selene FCMP++ curve tower.

HeliosField = Ed25519 base field  (p = 2^255 - 19, same as Field25519 in Rust)
SeleneField = novel field          (p = 0x7FFF...DF53; helioselene::HelioseleneField in Rust)

Both use little-endian 32-byte encoding, from_uniform_bytes = LE-int mod p.
"""

HELIOS_P = 2**255 - 19
SELENE_P = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF735481D1969F317F9850B68DF11DF53

# sqrt(-1) mod HELIOS_P  (= 2^((p-1)/4) mod p, used in RFC-8032 sqrt8k5)
_HELIOS_SQRT_M1 = pow(2, (HELIOS_P - 1) // 4, HELIOS_P)


class HeliosField:
    """Ed25519 base field: p = 2^255 - 19.

    Mirrors dalek_ff_group::FieldElement in the Rust codebase.
    """

    P = HELIOS_P

    __slots__ = ("v",)

    def __init__(self, value: int):
        self.v = int(value) % self.P

    # --- arithmetic ---

    def __add__(self, other: "HeliosField") -> "HeliosField":
        return HeliosField(self.v + other.v)

    def __sub__(self, other: "HeliosField") -> "HeliosField":
        return HeliosField(self.v - other.v)

    def __mul__(self, other: "HeliosField") -> "HeliosField":
        return HeliosField(self.v * other.v)

    def __neg__(self) -> "HeliosField":
        return HeliosField(-self.v)

    def __eq__(self, other) -> bool:
        if isinstance(other, HeliosField):
            return self.v == other.v
        return NotImplemented

    def __hash__(self):
        return hash(self.v)

    def __repr__(self) -> str:
        return f"HeliosField(0x{self.v:064x})"

    def __int__(self) -> int:
        return self.v

    # --- constants ---

    @classmethod
    def zero(cls) -> "HeliosField":
        return cls(0)

    @classmethod
    def one(cls) -> "HeliosField":
        return cls(1)

    def is_zero(self) -> bool:
        return self.v == 0

    def square(self) -> "HeliosField":
        return HeliosField(self.v * self.v)

    # --- field operations ---

    def inv(self) -> "HeliosField":
        if self.v == 0:
            raise ZeroDivisionError("invert of zero")
        return HeliosField(pow(self.v, self.P - 2, self.P))

    def sqrt(self):
        """RFC-8032 sqrt8k5 (p ≡ 5 mod 8).

        Returns a HeliosField or None if self is not a QR.
        Does NOT normalize to even — caller adjusts for sign.
        """
        p = self.P
        exp = (p + 3) // 8  # = 2^252 - 2
        tv1 = pow(self.v, exp, p)
        tv2 = tv1 * _HELIOS_SQRT_M1 % p
        if tv1 * tv1 % p == self.v:
            return HeliosField(tv1)
        if tv2 * tv2 % p == self.v:
            return HeliosField(tv2)
        return None

    def is_odd(self) -> bool:
        return bool(self.v & 1)

    # --- serialization ---

    def to_bytes(self) -> bytes:
        return self.v.to_bytes(32, "little")

    @classmethod
    def from_bytes(cls, b: bytes):
        """Deserialize 32 LE bytes. Returns None if value ≥ p."""
        if len(b) != 32:
            raise ValueError(f"expected 32 bytes, got {len(b)}")
        v = int.from_bytes(b, "little")
        if v >= cls.P:
            return None
        return cls(v)

    @classmethod
    def from_uniform_bytes(cls, b: bytes) -> "HeliosField":
        """64-byte LE integer reduced mod p. Matches FromUniformBytes<64>."""
        if len(b) != 64:
            raise ValueError(f"expected 64 bytes, got {len(b)}")
        return cls(int.from_bytes(b, "little") % cls.P)

    def to_le_bits(self) -> list:
        """256 bits, LSB first. Bit 255 is always 0 (both fields < 2^255)."""
        bits = []
        v = self.v
        for _ in range(256):
            bits.append(v & 1)
            v >>= 1
        return bits


class SeleneField:
    """Selene's base field: p = 0x7FFF...DF53 (== Helios's scalar field).

    Mirrors helioselene::HelioseleneField in the Rust codebase.
    """

    P = SELENE_P

    __slots__ = ("v",)

    def __init__(self, value: int):
        self.v = int(value) % self.P

    # --- arithmetic ---

    def __add__(self, other: "SeleneField") -> "SeleneField":
        return SeleneField(self.v + other.v)

    def __sub__(self, other: "SeleneField") -> "SeleneField":
        return SeleneField(self.v - other.v)

    def __mul__(self, other: "SeleneField") -> "SeleneField":
        return SeleneField(self.v * other.v)

    def __neg__(self) -> "SeleneField":
        return SeleneField(-self.v)

    def __eq__(self, other) -> bool:
        if isinstance(other, SeleneField):
            return self.v == other.v
        return NotImplemented

    def __hash__(self):
        return hash(self.v)

    def __repr__(self) -> str:
        return f"SeleneField(0x{self.v:064x})"

    def __int__(self) -> int:
        return self.v

    # --- constants ---

    @classmethod
    def zero(cls) -> "SeleneField":
        return cls(0)

    @classmethod
    def one(cls) -> "SeleneField":
        return cls(1)

    def is_zero(self) -> bool:
        return self.v == 0

    def square(self) -> "SeleneField":
        return SeleneField(self.v * self.v)

    # --- field operations ---

    def inv(self) -> "SeleneField":
        if self.v == 0:
            raise ZeroDivisionError("invert of zero")
        return SeleneField(pow(self.v, self.P - 2, self.P))

    def sqrt(self):
        """p ≡ 3 mod 4: sqrt = self^((p+1)/4), normalized to even.

        Returns a SeleneField or None if self is not a QR.
        """
        p = self.P
        res_v = pow(self.v, (p + 1) // 4, p)
        if res_v * res_v % p != self.v:
            return None
        res = SeleneField(res_v)
        if res.is_odd():
            res = -res
        return res

    def is_odd(self) -> bool:
        return bool(self.v & 1)

    # --- serialization ---

    def to_bytes(self) -> bytes:
        return self.v.to_bytes(32, "little")

    @classmethod
    def from_bytes(cls, b: bytes):
        """Deserialize 32 LE bytes. Returns None if value ≥ p."""
        if len(b) != 32:
            raise ValueError(f"expected 32 bytes, got {len(b)}")
        v = int.from_bytes(b, "little")
        if v >= cls.P:
            return None
        return cls(v)

    @classmethod
    def from_uniform_bytes(cls, b: bytes) -> "SeleneField":
        """64-byte LE integer reduced mod p. Matches FromUniformBytes<64>."""
        if len(b) != 64:
            raise ValueError(f"expected 64 bytes, got {len(b)}")
        return cls(int.from_bytes(b, "little") % cls.P)

    def to_le_bits(self) -> list:
        """256 bits, LSB first. Bit 255 is always 0 (both fields < 2^255)."""
        bits = []
        v = self.v
        for _ in range(256):
            bits.append(v & 1)
            v >>= 1
        return bits
