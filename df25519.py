
# import Keccak  # cn_fast_hash
import nacl.bindings
import nacl.utils
import binascii
import sha3
import time

class Scalar:
    def __init__(self, x):
        # Generated from an integer value
        if isinstance(x, int):
            self.b = x.to_bytes(32,"little") 
        # Generated from a hex representation or 'l'
        elif isinstance(x, str):
            try:
                if x == "l":
                    self.b = l  # technically not in scalar field; used for main subgroup membership
                else:
                    self.b = binascii.a2b_hex(x.encode("utf-8"))
            except:
                raise TypeError
        elif isinstance(x, bytes):
            try:
                self.b = x
            except:
                raise TypeError
        else:
            raise TypeError

    # Multiplicative inversion
    def invert(self: Scalar) -> Scalar:
        return Scalar(nacl.bindings.crypto_core_ed25519_scalar_invert(self.b))

    # Addition
    def __add__(self, y):
        if isinstance(y, Scalar):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_add(self.b,y.b))
        if isinstance(y,bytes):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_add(self.b,y))
        return NotImplemented

    # Subtraction
    def __sub__(self, y):
        if isinstance(y, Scalar):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_sub(self.b,y.b))
        if isinstance(y,bytes):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_sub(self.b,y))
        return NotImplemented

    # Multiplication (possibly by an integer)
    def __mul__(self, y):
        if isinstance(y, int):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_mul(self.b, bytes(y)))
        if isinstance(y, Scalar):
            return Scalar(nacl.bindings.crypto_core_ed25519_scalar_mul(self.b, y.b))
        return NotImplemented

    def __rmul__(self, y):
        if isinstance(y, int):
            return self * y
        return NotImplemented

    def __neg__(self):
        return Scalar(nacl.bindings.crypto_core_ed25519_scalar_negate(self.b))


    # Truncated division (possibly by a positive integer)
    def __truediv__(self, y):
        if isinstance(y, Scalar):
            return Scalar(self * invert(y))
        raise NotImplemented

    # Integer exponentiation
    def __pow__(self, y):
        if isinstance(y, int) and y >= 0:
            return Scalar(pow(self.to_int(),y,l))
        return NotImplemented

    # Equality
    def __eq__(self, y):
        if isinstance(y, Scalar):
            return self.b == y.b
        raise TypeError

    # Inequality
    def __ne__(self, y):
        if isinstance(y, Scalar):
            return self.b != y.b
        raise TypeError

    # Less-than comparison (does not account for overflow)
    def __lt__(self, y):
        if isinstance(y, Scalar):
            return self.to_int() < y.to_int()
        raise TypeError

    # Greater-than comparison (does not account for overflow)
    def __gt__(self, y):
        if isinstance(y, Scalar):
            return self.to_int() > y.to_int()
        raise TypeError

    # Hex representation
    def __repr__(self):
        return bytes.hex(self.b)

    # Return representing integer of stored bytes
    def to_int(self):
        return int.from_bytes(self.b,"little")


# An element of the curve group
class Point:
    def __init__(self, x):
        # Generated from integer values
        if isinstance(x, int):
            self.b = x.to_bytes(32,"little") 
        # Generated from a hex representation
        elif isinstance(x, str): 
            try:
                self.b = binascii.a2b_hex(x.encode("utf-8"))
            except:
                raise TypeError
        elif isinstance(x, bytes):
            try:
                self.b = x
            except:
                raise TypeError
        else:
            raise TypeError

    # Equality
    def __eq__(self, Q):
        if isinstance(Q, Point):
            return self.b == Q.b 
        raise TypeError

    # Inequality
    def __ne__(self, Q):
        if isinstance(Q, Point):
            return self.b != Q.b 
        raise TypeError

    # Addition
    def __add__(self, Q):
        if isinstance(Q, Point):
            return Point(nacl.bindings.crypto_core_ed25519_add(self.b,Q.b))
        elif isinstance(Q, bytes):
            return Point(nacl.bindings.crypto_core_ed25519_add(self.b,Q))
        return NotImplemented

    # Subtraction
    def __sub__(self, Q):
        if isinstance(Q, Point):
            return Point(nacl.bindings.crypto_core_ed25519_sub(self.b,Q.b))
        elif isinstance(Q, bytes):
            return Point(nacl.bindings.crypto_core_ed25519_sub(self.b,Q))
        return NotImplemented

    # Multiplication
    def __mul__(self, y):
        if isinstance(y, Scalar):
            try:
                return Point(nacl.bindings.crypto_scalarmult_ed25519_noclamp(y.b, self.b))
            except Exception as inst:
                return "Error in multiplication"
        return NotImplemented

    def scalar_mult(s):
        try:
            return Point(nacl.bindings.crypto_scalarmult_ed25519_noclamp(s.b, self.b))
        except Exception as inst:
            return "Error in multiplication"
        return NotImplemented

    def scalar_mult_base(self, s):
        try:
            return Point(nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(s.b))
        except Exception as inst:
            return "Error in multiplication"
        return NotImplemented

    def __rmul__(self, y):
        # Scalar-Point
        if isinstance(y, Scalar):
            return self * y
        return NotImplemented

    # Hex representation
    def __repr__(self):
        return bytes.hex(self.b)

    # Curve membership (not main subgroup!)
    def on_curve(self):
        return nacl.bindings.crypto_core_ed25519_is_valid_point(self.b)

# A vector of Points with superpowers
class PointVector:
    def __init__(self, points=None):
        if points is None:
            points = []
        for point in points:
            if not isinstance(point, Point):
                raise TypeError
        self.points = points

    # Equality
    def __eq__(self, W):
        if isinstance(W, PointVector):
            return self.points == W.points
        raise TypeError

    # Inequality
    def __ne__(self, W):
        if isinstance(W, PointVector):
            return self.points != W.points
        raise TypeError

    # Addition
    def __add__(self, W):
        if isinstance(W, PointVector) and len(self.points) == len(W.points):
            return PointVector(
                [self.points[i] + W.points[i] for i in range(len(self.points))]
            )
        return NotImplemented

    # Subtraction
    def __sub__(self, W):
        if isinstance(W, PointVector) and len(self.points) == len(W.points):
            return PointVector(
                [self.points[i] - W.points[i] for i in range(len(self.points))]
            )
        return NotImplemented

    # multiplying a PointVector by a scalar or ScalarVector or Hadamard
    def __mul__(self, s):
        if isinstance(s, Scalar):
            return PointVector([self.points[i] * s for i in range(len(self.points))])
        if isinstance(s, ScalarVector):
            return multiexp_naive(s, self)
        if isinstance(s, PointVector):
            if not len(self.points) == len(s.points):
                raise IndexError
            return PointVector(
                [self.points[i] + s.points[i] for i in range(len(self.points))]
            )
        raise TypeError

    def __rmul__(self, s):
        # Scalar-PointVector
        if isinstance(s, Scalar):
            return self * s
        # ScalarVector-PointVector
        if isinstance(s, ScalarVector):
            return self * s
        return NotImplemented

    # Multiscalar multiplication
    def __pow__(self, s):
        if isinstance(s, ScalarVector) and len(self.points) == len(s.scalars):
            return multiexp_naive(s, self)
        return NotImplemented

    # Length
    def __len__(self):
        return len(self.points)

    # Get slice
    def __getitem__(self, i):
        if not isinstance(i, slice):
            return self.points[i]
        return PointVector(self.points[i])

    # Set at index
    def __setitem__(self, i, P):
        if isinstance(P, Point):
            self.points[i] = P
        else:
            raise TypeError

    # Append
    def append(self, item):
        if isinstance(item, Point):
            self.points.append(item)
        else:
            raise TypeError

    # Extend
    def extend(self, items):
        if isinstance(items, PointVector):
            for item in items.points:
                self.points.append(item)
        else:
            raise TypeError

    # Hex representation of underlying Points
    def __repr__(self):
        return repr(self.points)

    # Negation
    def __neg__(self):
        return PointVector([-P for P in self.points])


# A vector of Scalars with superpowers
class ScalarVector:
    def __init__(self, scalars=None):
        if scalars is None:
            scalars = []
        for scalar in scalars:
            if not isinstance(scalar, Scalar):
                raise TypeError
        self.scalars = scalars

    # Equality
    def __eq__(self, s):
        if isinstance(s, ScalarVector):
            return self.scalars == s.scalars
        raise TypeError

    # Inequality
    def __ne__(self, s):
        if isinstance(s, ScalarVector):
            return self.scalars != s.scalars
        raise TypeError

    # Addition
    def __add__(self, s):
        if isinstance(s, ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector(
                [self.scalars[i] + s.scalars[i] for i in range(len(self.scalars))]
            )
        return NotImplemented

    # Subtraction
    def __sub__(self, s):
        if isinstance(s, ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector(
                [self.scalars[i] - s.scalars[i] for i in range(len(self.scalars))]
            )
        return NotImplemented

    # Multiplication
    def __mul__(self, s):
        # ScalarVector-Scalar: componentwise Scalar-Scalar multiplication
        if isinstance(s, Scalar):
            return ScalarVector([self.scalars[i] * s for i in range(len(self.scalars))])
        # ScalarVector-ScalarVector: Hadamard product
        if isinstance(s, ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector(
                [self.scalars[i] * s.scalars[i] for i in range(len(self.scalars))]
            )
        return NotImplemented

    def __rmul__(self, s):
        # Scalar-ScalarVector
        if isinstance(s, Scalar):
            return self * s
        return NotImplemented

    # Sum of all Scalars
    def sum(self):
        r = Scalar(0)
        for i in range(len(self.scalars)):
            r += self.scalars[i]
        return r

    # Inner product and multiscalar multiplication
    def __pow__(self, s):
        # ScalarVector**ScalarVector: inner product
        if isinstance(s, ScalarVector) and len(self.scalars) == len(s.scalars):
            r = Scalar(0)
            for i in range(len(self.scalars)):
                r += self.scalars[i] * s.scalars[i]
            return r
        # ScalarVector**PointVector: multiscalar multiplication
        if isinstance(s, PointVector):
            return s**self
        return NotImplemented

    # Length
    def __len__(self):
        return len(self.scalars)

    # Get slice
    def __getitem__(self, i):
        if not isinstance(i, slice):
            return self.scalars[i]
        return ScalarVector(self.scalars[i])

    # Set at index
    def __setitem__(self, i, s):
        if isinstance(s, Scalar):
            self.scalars[i] = s
        else:
            raise TypeError

    # Append
    def append(self, item):
        if isinstance(item, Scalar):
            self.scalars.append(item)
        else:
            raise TypeError

    # Extend
    def extend(self, items):
        if isinstance(items, ScalarVector):
            for item in items.scalars:
                self.scalars.append(item)
        else:
            raise TypeError

    # Hex representation of underlying Scalars
    def __repr__(self):
        return repr(self.scalars)

    # Componentwise inversion (possibly with zero)
    def invert(self, allow_zero=False):
        # If we allow zero, the efficient method doesn't work
        if allow_zero:
            return ScalarVector([s.invert(allow_zero=True) for s in self.scalars])

        # Don't allow zero
        inputs = self.scalars[:]
        n = len(inputs)
        scratch = [Scalar(1)] * n
        acc = Scalar(1)

        for i in range(n):
            if inputs[i] == Scalar(0):
                raise ZeroDivisionError
            scratch[i] = acc
            acc *= inputs[i]
        acc = Scalar(invert(acc.to_int(), l))
        for i in range(n - 1, -1, -1):
            temp = acc * inputs[i]
            inputs[i] = acc * scratch[i]
            acc = temp

        return ScalarVector(inputs)

    # Negation
    def __neg__(self):
        return ScalarVector([-s for s in self.scalars])


# Perform a naive multiscalar multiplication 
def multiexp_naive(scalars, points):
    if not isinstance(scalars, ScalarVector) or not isinstance(points, PointVector):
        raise TypeError

    if len(scalars) != len(points):
        raise IndexError
    if len(scalars) == 0:
        return Z

    result = Z
    for i in range(len(scalars)):
        result += scalars[i]*points[i]
    
    return result

# Perform a multiscalar multiplication using a simplified Pippenger algorithm
def multiexp(scalars, points):

    if not isinstance(scalars, ScalarVector) or not isinstance(points, PointVector):
        raise TypeError

    if len(scalars) != len(points):
        raise IndexError
    if len(scalars) == 0:
        return Z

    buckets = None
    result = Z  # zero point

    c = 5 # window parameter; NOTE: the optimal value actually depends on len(points) empirically

    # really we want to use the max bitlength to compute groups
    maxscalar = 0
    for s in scalars:
        if s.to_int()>maxscalar:
            maxscalar = s.to_int()

    # import ipdb;ipdb.set_trace()

    groups = 0
    while maxscalar >= 2**groups:
        groups += 1
    groups = int((groups + c - 1) / c)

    # loop is really (groups-1)..0
    for k in range(groups - 1, -1, -1):
        if result != Z:
            for i in range(c):
                result += result

        buckets = [Z] * (1<<c)  # clear all buckets

        # partition scalars into buckets
        for i in range(len(scalars)):
            bucket = 0
            for j in range(c):
                if scalars[i].to_int() & (1 << (k * c + j)):  # test for bit
                    bucket |= 1 << j

            if bucket == 0:  # zero bucket is never used
                continue

            if buckets[bucket] != Z:
                buckets[bucket] += points[i]
            else:
                buckets[bucket] = points[i]

        # sum the buckets
        pail = Z
        for i in range(len(buckets) - 1, 0, -1):
            if buckets[i] != Z:
                pail += buckets[i]
            if pail != Z:
                result += pail
    return result

def random_scalar():
    return Scalar(nacl.utils.random())

def random_point():
    return hash_to_point("{:x}".format(secrets.randbits(b)))

def cn_fast_hash(s):
    m = sha3.keccak_256()
    m.update(binascii.a2b_hex(s))
    return m.hexdigest()

def hash_to_scalar(data):
    return Scalar(hex_to_int(cn_fast_hash(data)) % l)

def hash_to_point(hex_value):
    u = hex_to_int(cn_fast_hash(hex_value)) % q
    A = 486662
    ma = -1 * A % q
    ma2 = -1 * A * A % q
    sqrtm1 = sqroot(-1)

    w = (2 * u * u + 1) % q
    xp = (w * w - 2 * A * A * u * u) % q
    rx = expmod(w * inv(xp), ((q + 3) // 8), q)
    x = rx * rx * (w * w - 2 * A * A * u * u) % q
    y = (2 * u * u + 1 - x) % q  # w - x, if y is zero, then x = w

    negative = False
    if y != 0:
        y = (w + x) % q  # checking if you got the negative square root.
        if y != 0:
            negative = True
        else:
            rx = rx * -1 * sqroot(-2 * A * (A + 2)) % q
            negative = False
    else:
        # y was 0..
        rx = (rx * -1 * sqroot(2 * A * (A + 2))) % q
    if not negative:
        rx = (rx * u) % q
        z = (-2 * A * u * u) % q
        sign = 0
    else:
        z = -1 * A
        x = x * sqrtm1 % q  # ..
        y = (w - x) % q
        if y != 0:
            rx = rx * sqroot(-1 * sqrtm1 * A * (A + 2)) % q
        else:
            rx = rx * -1 * sqroot(sqrtm1 * A * (A + 2)) % q
        sign = 1
    # setsign
    if (rx % 2) != sign:
        rx = -(rx) % q
    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q

    P = point_compress([rx, ry, rz])
    P8 = P + P + P + P + P + P + P + P
    return P8


# Necessery functions for hash_to_point
def sqroot(xx):
    x = expmod(xx, ((q + 3) // 8), q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if (x * x - xx) % q != 0:
        print("no square root!")
    return x

def hex_to_int(h):
    # Input: String with hex value
    # Output: Int value corresponding
    # Conversion uses little indian. The function int(h,16) wont work as it uses big indian.
    return int.from_bytes(bytes.fromhex(h), "little")

def int_to_hex(h):
    return h.to_bytes(32,"little").hex()

# Internal helper methods
def exponent(b, e, m):
    return pow(b, e, m)

def modp_inv(x):
    return pow(x, p - 2, p)

def expmod(b, e, m):
    return pow(b, e, m)

def inv(x):
    return pow(x, q - 2, q)

def invert(x, p):
    # Assumes `p` is prime
    return exponent(x, p - 2, p)

def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p

    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    
    bb = Point(bytes.hex(bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8)])))

    return bb 

def verify_subgroup(P):
    return nacl.bindings.crypto_core_ed25519_is_valid_point(P.b)


# Curve parameters
# k = Keccak.Keccak()
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
cofactor = 8
b = 256  # bit length
p = 2**255 - 19
d = -121665 * invert(121666, q)
I = exponent(2, (q - 1) // 4, q)

G = Point('5866666666666666666666666666666666666666666666666666666666666666')
H = Scalar(8) * Point(cn_fast_hash(str(G)))
# Neutral group element
Z = Point(1)