"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "Dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
# dumber25519: an even more stupid implementation of ed25519

import secrets
import Keccak #cn_fast_hash

import time
import nacl.bindings
import binascii

# Curve parameters
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
cofactor = 8
b = 256 # bit length
p = 2**255 - 19


# Internal helper methods
def exponent(b,e,m):
    return pow(b,e,m)

def invert(x,p):
    # Assumes `p` is prime
    return exponent(x,p-2,p)

def xfromy(y):
    temp = (y*y-1) * invert(d*y*y+1,q)
    x = exponent(temp,(q+3)//8,q)
    if (x*x - temp) % q != 0:
        x = (x*I) % q
    if x % 2 != 0:
        x = q-x
    return x

def xfromy_ztm(y):
    # Not working

    biny = bin(y)
    b = biny[-1]
    newbin = biny[:-1]
    newy = newbin + '0'
    y = int(newy,2)
    xp = 0

    import ipdb;ipdb.set_trace()
    u = (y*y - 1) % q 
    v = (d*y*y + 1) % q
    z = (u * v**3) * exponent(u*v**7,((q-5)//8), q) % q
    if ((v*z**2) % q) == (u % q):
        xp = (z % q)
    if ((v*z**2) % q) == (-u % q):
        xp = z * 2**((q-1)//4) % q

    if b != bin(xp)[-1]:
        return -xp % q
    else:
        return xp % q



def bit(h,i):
    return (int(h[i//8]) >> (i%8)) & 1


# An element of the main subgroup scalar field
class Scalar:
    def __init__(self,x):
        # Generated from an integer value
        if isinstance(x,int):
            self.x = x % l
        # Generated from a hex representation or 'l'
        elif isinstance(x,str):
            try:
                if x == 'l':
                    self.x = l # technically not in scalar field; used for main subgroup membership
                else:
                    x = bytes.fromhex(x)
                    self.x = sum(2**i * bit(x,i) for i in range(0,b)) % l
            except:
                raise TypeError
        else:
            raise TypeError

    # Multiplicative inversion, with an option to let 1/0 = 0 if you're into that
    def invert(self,allow_zero=False):
        if self.x == 0:
            if allow_zero:
                return Scalar(0)
            else:
                raise ZeroDivisionError
        return Scalar(invert(self.x,l))

    # Addition
    def __add__(self,y):
        if isinstance(y,Scalar):
            return Scalar(self.x + y.x)
        return NotImplemented

    # Subtraction
    def __sub__(self,y):
        if isinstance(y,Scalar):
            return Scalar(self.x - y.x)
        return NotImplemented

    # Multiplication (possibly by an integer)
    def __mul__(self,y):
        if isinstance(y,int):
            return Scalar(self.x * y)
        if isinstance(y,Scalar):
            return Scalar(self.x * y.x)
        return NotImplemented

    def __rmul__(self,y):
        if isinstance(y,int):
            return self*y
        return NotImplemented

    # Truncated division (possibly by a positive integer)
    def __truediv__(self,y):
        if isinstance(y,int) and y >= 0:
            return Scalar(self.x // y)
        if isinstance(y,Scalar):
            return Scalar(self.x // y.x)
        raise NotImplemented

    # Integer exponentiation
    def __pow__(self,y):
        if isinstance(y,int) and y >= 0:
            return Scalar(self.x**y)
        return NotImplemented

    # Equality
    def __eq__(self,y):
        if isinstance(y,Scalar):
            return self.x == y.x
        raise TypeError

    # Inequality
    def __ne__(self,y):
        if isinstance(y,Scalar):
            return self.x != y.x
        raise TypeError

    # Less-than comparison (does not account for overflow)
    def __lt__(self,y):
        if isinstance(y,Scalar):
            return self.x < y.x
        raise TypeError

    # Greater-than comparison (does not account for overflow)
    def __gt__(self,y):
        if isinstance(y,Scalar):
            return self.x > y.x
        raise TypeError

    # Less-than-or-equal comparison (does not account for overflow)
    def __le__(self,y):
        if isinstance(y,Scalar):
            return self.x <= y.x
        raise TypeError

    # Greater-than-or-equal comparison (does not account for overflow)
    def __ge__(self,y):
        if isinstance(y,Scalar):
            return self.x >= y.x
        raise TypeError

    # Hex representation
    def __repr__(self):
        bits = [(self.x >> i) & 1 for i in range(b)]
        return bytes.hex(bytes([sum([bits[i*8+j] << j for j in range(8)]) for i in range(b//8)]))

    # Return underlying integer
    def __int__(self):
        return self.x

    # Modulus (possibly by an integer)
    def __mod__(self,mod):
        if isinstance(mod,int) and mod > 0:
            return Scalar(self.x % mod)
        if isinstance(mod,Scalar) and mod != Scalar(0):
            return Scalar(self.x % mod.x)
        return NotImplemented

    # Negation
    def __neg__(self):
        return Scalar(-self.x)

# An element of the curve group
class Point:
    def __init__(self,x,y=None):
        # Generated from integer values
        if isinstance(x,int) and isinstance(y,int) and y is not None:
            self.x = x
            self.y = y

            if not self.on_curve():
                raise ValueError
        # Generated from a hex representation
        elif isinstance(x,str) and y is None:
            try:
                x = bytes.fromhex(x)
                self.y = sum(2**i * bit(x,i) for i in range(0,b-1))
                self.x = xfromy(self.y)
                if self.x & 1 != bit(x,b-1):
                    self.x = q - self.x
            except:
                raise TypeError

            if not self.on_curve():
                raise ValueError
        else:
            raise TypeError

    # Equality
    def __eq__(self,Q):
        if isinstance(Q,Point):
            return self.x == Q.x and self.y == Q.y
        raise TypeError

    # Inequality
    def __ne__(self,Q):
        if isinstance(Q,Point):
            return self.x != Q.x or self.y != Q.y
        raise TypeError
    
    # Addition
    def __add__(self,Q):
        if isinstance(Q,Point):
            x1 = self.x
            y1 = self.y
            x2 = Q.x
            y2 = Q.y
            x3 = (x1*y2+x2*y1) * invert(1+d*x1*x2*y1*y2,q)
            y3 = (y1*y2+x1*x2) * invert(1-d*x1*x2*y1*y2,q)
            return Point(x3 % q, y3 % q)
        return NotImplemented

    # Subtraction
    def __sub__(self,Q):
        if isinstance(Q,Point):
            x1 = self.x
            y1 = self.y
            x2 = -Q.x
            y2 = Q.y
            x3 = (x1*y2+x2*y1) * invert(1+d*x1*x2*y1*y2,q)
            y3 = (y1*y2+x1*x2) * invert(1-d*x1*x2*y1*y2,q)
            return Point(x3 % q, y3 % q)
        return NotImplemented

    # Multiplication
    # def __mul__(self,y):
        # # Point-Scalar: scalar multiplication
        # if isinstance(y,Scalar):
            # if y == Scalar(0):
                # return Point(0,1)
            # Q = self.__mul__(y/Scalar(2))
            # Q = Q.__add__(Q)
            # if y.x & 1:
                # Q = self.__add__(Q)
            # return Q
        # return NotImplemented

    # Multiplication
    def __mul__(self,y):
        # Point-Scalar: scalar multiplication
        if isinstance(y,Scalar):
            if y == Scalar(0):
                return Point(0,1)
            try:
                sk = binascii.a2b_hex(str(y).encode('utf-8'))
                pk = binascii.a2b_hex(str(self).encode('utf-8'))
                Q = nacl.bindings.crypto_scalarmult_ed25519_noclamp(sk,pk)
                # return Point(nacl.bindings.crypto_scalarmult_ed25519_noclamp(binascii.a2b_hex(str(y).encode('utf-8')),binascii.a2b_hex(str(self).encode('utf-8'))).hex())
                return Point(Q.hex())

            except Exception as inst:
                print('Warning, error in multiplying point: '+str(self) +' by scalar: '+str(y))    # the exception instance
                print('You should stop and verify this multiplication. It seems outside of the allowed Monero subgroup.')    # the exception instance
                with open("error.txt", "w+") as file1:
                    # Writing data to a file
                    file1.write('Warning, error in multiplying point: '+str(self) +' by scalar: '+str(y))
                # print('Args: ',inst.args)     # arguments stored in .args
                # print('Inst: ',inst)
                return Point(0,1)

        return NotImplemented


    def __rmul__(self,y):
        # Scalar-Point
        if isinstance(y,Scalar):
            return self*y
        return NotImplemented

    # Hex representation
    def __repr__(self):
        bits = [(self.y >> i) & 1 for i in range(b-1)] + [self.x & 1]
        return bytes.hex(bytes([sum([bits[i*8+j] << j for j in range(8)]) for i in range(b//8)]))

    # Curve membership (not main subgroup!)
    def on_curve(self):
        x = self.x
        y = self.y
        return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

    # Negation
    def __neg__(self):
        return Z - self

# A vector of Points with superpowers
class PointVector:
    def __init__(self,points=None):
        if points is None:
            points = []
        for point in points:
            if not isinstance(point,Point):
                raise TypeError
        self.points = points

    # Equality
    def __eq__(self,W):
        if isinstance(W,PointVector):
            return self.points == W.points
        raise TypeError

    # Inequality
    def __ne__(self,W):
        if isinstance(W,PointVector):
            return self.points != W.points
        raise TypeError

    # Addition
    def __add__(self,W):
        if isinstance(W,PointVector) and len(self.points) == len(W.points):
            return PointVector([self.points[i] + W.points[i] for i in range(len(self.points))])
        return NotImplemented

    # Subtraction
    def __sub__(self,W):
        if isinstance(W,PointVector) and len(self.points) == len(W.points):
            return PointVector([self.points[i] - W.points[i] for i in range(len(self.points))])
        return NotImplemented

    # Multiplication
    def __mul__(self,s):
        # PointVector-Scalar: componentwise Point-Scalar multiplication
        if isinstance(s,Scalar):
            return PointVector([self.points[i]*s for i in range(len(self.points))])
        # PointVector-ScalarVector: Hadamard product
        if isinstance(s,ScalarVector) and len(self.points) == len(s.scalars):
            return PointVector([s[i]*self[i] for i in range(len(self))])
        return NotImplemented

    def __rmul__(self,s):
        # Scalar-PointVector
        if isinstance(s,Scalar):
            return self*s
        # ScalarVector-PointVector
        if isinstance(s,ScalarVector):
            return self*s
        return NotImplemented

    # Multiscalar multiplication
    def __pow__(self,s):
        if isinstance(s,ScalarVector) and len(self.points) == len(s.scalars):
            return multiexp(s,self)
        return NotImplemented

    # Length
    def __len__(self):
        return len(self.points)

    # Get slice
    def __getitem__(self,i):
        if not isinstance(i,slice):
            return self.points[i]
        return PointVector(self.points[i])

    # Set at index
    def __setitem__(self,i,P):
        if isinstance(P,Point):
            self.points[i] = P
        else:
            raise TypeError

    # Append
    def append(self,item):
        if isinstance(item,Point):
            self.points.append(item)
        else:
            raise TypeError

    # Extend
    def extend(self,items):
        if isinstance(items,PointVector):
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
    def __init__(self,scalars=None):
        if scalars is None:
            scalars = []
        for scalar in scalars:
            if not isinstance(scalar,Scalar):
                raise TypeError
        self.scalars = scalars

    # Equality
    def __eq__(self,s):
        if isinstance(s,ScalarVector):
            return self.scalars == s.scalars
        raise TypeError

    # Inequality
    def __ne__(self,s):
        if isinstance(s,ScalarVector):
            return self.scalars != s.scalars
        raise TypeError

    # Addition
    def __add__(self,s):
        if isinstance(s,ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector([self.scalars[i] + s.scalars[i] for i in range(len(self.scalars))])
        return NotImplemented

    # Subtraction
    def __sub__(self,s):
        if isinstance(s,ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector([self.scalars[i] - s.scalars[i] for i in range(len(self.scalars))])
        return NotImplemented

    # Multiplication
    def __mul__(self,s):
        # ScalarVector-Scalar: componentwise Scalar-Scalar multiplication 
        if isinstance(s,Scalar):
            return ScalarVector([self.scalars[i]*s for i in range(len(self.scalars))])
        # ScalarVector-ScalarVector: Hadamard product
        if isinstance(s,ScalarVector) and len(self.scalars) == len(s.scalars):
            return ScalarVector([self.scalars[i]*s.scalars[i] for i in range(len(self.scalars))])
        return NotImplemented

    def __rmul__(self,s):
        # Scalar-ScalarVector
        if isinstance(s,Scalar):
            return self*s
        return NotImplemented

    # Sum of all Scalars
    def sum(self):
        r = Scalar(0)
        for i in range(len(self.scalars)):
            r += self.scalars[i]
        return r

    # Inner product and multiscalar multiplication
    def __pow__(self,s):
        # ScalarVector**ScalarVector: inner product
        if isinstance(s,ScalarVector) and len(self.scalars) == len(s.scalars):
            r = Scalar(0)
            for i in range(len(self.scalars)):
                r += self.scalars[i]*s.scalars[i]
            return r
        # ScalarVector**PointVector: multiscalar multiplication
        if isinstance(s,PointVector):
            return s**self
        return NotImplemented

    # Length
    def __len__(self):
        return len(self.scalars)

    # Get slice
    def __getitem__(self,i):
        if not isinstance(i,slice):
            return self.scalars[i]
        return ScalarVector(self.scalars[i])

    # Set at index
    def __setitem__(self,i,s):
        if isinstance(s,Scalar):
            self.scalars[i] = s
        else:
            raise TypeError

    # Append
    def append(self,item):
        if isinstance(item,Scalar):
            self.scalars.append(item)
        else:
            raise TypeError

    # Extend
    def extend(self,items):
        if isinstance(items,ScalarVector):
            for item in items.scalars:
                self.scalars.append(item)
        else:
            raise TypeError

    # Hex representation of underlying Scalars
    def __repr__(self):
        return repr(self.scalars)

    # Componentwise inversion (possibly with zero)
    def invert(self,allow_zero=False):
        # If we allow zero, the efficient method doesn't work
        if allow_zero:
            return ScalarVector([s.invert(allow_zero=True) for s in self.scalars])

        # Don't allow zero
        inputs = self.scalars[:]
        n = len(inputs)
        scratch = [Scalar(1)]*n
        acc = Scalar(1)

        for i in range(n):
            if inputs[i] == Scalar(0):
                raise ZeroDivisionError
            scratch[i] = acc
            acc *= inputs[i]
        acc = Scalar(invert(acc.x,l))
        for i in range(n-1,-1,-1):
            temp = acc*inputs[i]
            inputs[i] = acc*scratch[i]
            acc = temp

        return ScalarVector(inputs)

    # Negation
    def __neg__(self):
        return ScalarVector([-s for s in self.scalars])

# Try to make a point from a given y-coordinate
def make_point(y):
    if not y < q: # stay in the field
        return None
    x = xfromy(y)
    try:
        P = Point(x,y)
    except ValueError:
        return None
    return P

def sqroot(xx):
    x = expmod(xx, ((q + 3) // 8), q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if (x * x - xx) % q != 0:
        print("no square root!")
    return x


def theD():
    return d


def computeA():
    return 2 * ((1 - d) % q) * inv((1 + d) % q) % q


def expmod(b, e, m):
    return pow(b, e, m)


def modp_inv(x):
    return pow(x, p - 2, p)


def inv(x):
    return pow(x, q - 2, q)


def hash_to_point(hexVal):
    u = hexToInt(cn_fast_hash(hexVal)) % q
    A = 486662
    ma = -1 * A % q
    ma2 = -1 * A * A % q
    sqrtm1 = sqroot(-1)
    d = theD()  # print(radix255(d))
    fffb1 = -1 * sqroot(-2 * A * (A + 2))
    #print("fffb1", ed25519.radix255(fffb1))
    fffb2 = -1 * sqroot(2 * A * (A + 2))
    #print("fffb2", ed25519.radix255(fffb2))
    fffb3 = sqroot(-1 * sqrtm1 * A * (A + 2))
    #print("fffb3", ed25519.radix255(fffb3))
    fffb4 = -1 * sqroot(sqrtm1 * A * (A + 2))
    #print("fffb4", ed25519.radix255(fffb4))

    w = (2 * u * u + 1) % q
    xp = (w * w - 2 * A * A * u * u) % q
    rx = expmod(w * inv(xp), ((q + 3) // 8), q)
    x = rx * rx * (w * w - 2 * A * A * u * u) % q
    y = (2 * u * u + 1 - x) % q  # w - x, if y is zero, then x = w

    negative = False
    if (y != 0):
        y = (w + x) % q  # checking if you got the negative square root.
        if (y != 0):
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
        if (y != 0):
            rx = rx * sqroot(-1 * sqrtm1 * A * (A + 2)) % q
        else:
            rx = rx * -1 * sqroot(sqrtm1 * A * (A + 2)) % q
        sign = 1
    # setsign
    if ((rx % 2) != sign):
        rx = - (rx) % q
    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q

    # import ipdb;ipdb.set_trace()
    P = point_compress([rx, ry, rz])
    # P8 = P * Scalar(8)
    P8 = P + P + P + P + P + P + P + P
    return P8


def hash_to_scalar(data):
    res = cn_fast_hash(data)
    return sc_reduce32(res)

def cn_fast_hash(s):
    k = Keccak.Keccak()
    return k.Keccak((len(s) * 4, s), 1088, 512, 32 * 8, False).lower() #r = bitrate = 1088, c = capacity, n = output length in bits

def hexToInt(h):
    # Input: String with hex value
    # Output: Int value corresponding
    # Conversion uses little indian. The function int(h,16) wont work as it uses big indian.
    return int.from_bytes(bytes.fromhex(h), "little")

# Generate a random Scalar
def random_scalar(zero=True):
    value = Scalar(secrets.randbelow(l))
    if not zero and value == Scalar(0):
        raise ValueError('Random scalar unexpectedly returned zero!')
    return value

# Generate a random Point in the main subgroup
def random_point():
    return hash_to_point("{:x}".format(secrets.randbits(b)))


# Perform a multiscalar multiplication using a simplified Pippenger algorithm
def multiexp(scalars,points):
    if not isinstance(scalars,ScalarVector) or not isinstance(points,PointVector):
        raise TypeError

    if len(scalars) != len(points):
        raise IndexError
    if len(scalars) == 0:
        return Z

    buckets = None
    result = Z # zero point
   
    c = 4 # window parameter; NOTE: the optimal value actually depends on len(points) empirically

    # really we want to use the max bitlength to compute groups
    maxscalar = int(max(scalars))
    groups = 0
    while maxscalar >= 2**groups:
        groups += 1
    groups = int((groups + c - 1) / c)
    
    # loop is really (groups-1)..0
    for k in range(groups-1,-1,-1):
        if result != Z:
            for i in range(c):
                result += result
        
        buckets = [Z]*(2**c) # clear all buckets
        
        # partition scalars into buckets
        for i in range(len(scalars)):
            bucket = 0
            for j in range(c):
                if int(scalars[i]) & (1 << (k*c+j)): # test for bit
                    bucket |= 1 << j
            
            if bucket == 0: # zero bucket is never used
                continue
            
            if buckets[bucket] != Z:
                buckets[bucket] += points[i]
            else:
                buckets[bucket] = points[i]
        
        # sum the buckets
        pail = Z
        for i in range(len(buckets)-1,0,-1):
            if buckets[i] != Z:
                pail += buckets[i]
            if pail != Z:
                result += pail
    return result

#### Functions to check ring signatures v1

def scalarmultBase(sk):
    # returns pubkey in hex, expects hex sk
    return public_key(sk)

def ge_frombytes_vartime(img):
    return 0

def public_key(sk):
    # Input: Scalar (secret key)
    # Output: Point (Public key)
    pk = sk * G
    return pk

def hexToInt(h):
    # Input: String with hex value
    # Output: Int value corresponding
    # Conversion uses little indian. The function int(h,16) wont work as it
    # uses big indian.
    return int.from_bytes(bytes.fromhex(h), "little")

def publicFromSecret(sk):
    # returns pubkey in hex, same as scalarmultBase
    return binascii.hexlify(public_key(hexToInt(sk)))


def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    # Ptest = dumber25519.make_point(y)
    # if Ptest.x != x:
    # print('Something wrong here!!!! make_point not working')
    # import ipdb;ipdb.set_trace()
    # Function dumber25519.make_point(y) is wrong
    return Point(x, y)


def sc_reduce32(data):
    return Scalar(hexToInt(data) % l)


def ge_double_scalarmult_base_vartime(aa, AA, bb):
    tmpa = aa * AA
    tmpb = bb * G
    return tmpa + tmpb


def ge_double_scalarmult_vartime(aa, AA, bb, BB):
    tmpa = aa * AA
    tmpb = bb * BB
    return tmpa + tmpb

def sc_add(aa, bb):
    return (aa + bb) % l

def sc_sub(aa, bb):
    return (aa - bb) % l

def sc_isnonzero(c):
    return (c % q != Scalar(0))

def sc_mulsub(aa, bb, cc):
    return (cc - aa * bb) % l

def sc_check(a):
    if a == Scalar(0):
        return False
    return (a == sc_reduce_key(a))

def sc_reduce_key(a):
    return a % l

# Other constants
d = -121665 * invert(121666,q)
I = exponent(2,(q-1)//4,q)

# The main subgroup default generator
Gy = 4*invert(5,q)
Gx = xfromy(Gy)
G = Point(Gx % q, Gy % q)
H = Scalar(8) * Point(cn_fast_hash(str(G)))

# Neutral group element
Z = Point(0,1)
