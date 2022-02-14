#ed25519.cr.yp.to/python/ed25519.py
import hashlib

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

import sys
print(sys.setrecursionlimit(5000))


def H(m):
  return hashlib.sha512(m).digest()


def expmod(b,e,m):
    return pow(b,e,m)


def inv(x):
  return pow(x,q-2,q)

d = -121665 * inv(121666)
I = expmod(2,((q-1)//4),q)

def radix255(x):
    x = x % q
    if x + x > q: x -= q
    x = [x,0,0,0,0,0,0,0,0,0]
    bits = [26,25,26,25,26,25,26,25,26,25]
    for i in range(9):
        carry = (x[i] + 2**(bits[i]-1)) / 2**bits[i]
        x[i] -= carry * 2**bits[i]
        x[i + 1] += carry
    result = ""
    for i in range(9):
        result = result+str(x[i])+","
    result = result+str(x[9])
    return result

def theD():
    return d

def computeA():
  return 2 *((1 - d) % q) * inv((1 + d) % q) % q

def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  x = expmod(xx,((q+3)//8),q)
  if (x*x - xx) % q != 0: x = (x*I) % q
  if x % 2 != 0: x = q-x
  return x

def sqroot(xx):
  x = expmod(xx,((q+3)//8),q)
  if (x*x - xx) % q != 0: 
    x = (x*I) % q
  if (x*x - xx) % q != 0: 
    print("no square root!")
  return x

  

By = 4 * inv(5) 
Bx = xrecover(By)
B = [Bx % q,By % q]

def edwards(P,Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2) 
  return [x3 % q,y3 % q]

def edwards_Minus(P, Q): #added 
  x1 = P[0]
  y1 = P[1]
  x2 = (-1 * Q[0]) % q
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2) 
  return [x3 % q,y3 % q]


def scalarmult(P,e):
  if e == 0: return [0,1]
  Q = scalarmult(P,e/2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return Q

#added scalarmultbase
def scalarmultbase(e):
  if e == 0: return [0,1]
  Q = scalarmult(B,e/2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,B)
  return Q

def encodeint(y):
  bits = [(y >> i) & 1 for i in range(b)]
  return ''.join([chr(sum([bits[int(i * 8 + j)] << j for j in range(8)])) for i in range(int(b/8))])

# def encodeint(y):
  # bits = [(y >> i) & 1 for i in range(b)]
  # return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])


def encodepoint(P):
  x = P[0]
  y = P[1]
  bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
  return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

# def encodepoint(P):
  # x = P[0]
  # y = P[1]
  # bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
  # return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

# def bit(h,i):
  # return (ord(h[i/8]) >> (i%8)) & 1

def bit(h,i):
    return (int(h[i//8]) >> (i%8)) & 1

def publickey(sk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  A = scalarmult(B,a)
  return encodepoint(A)

def Hint(m):
  h = H(m)
  return sum(2**i * bit(h,i) for i in range(2*b))

def signature(m,sk,pk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  r = Hint(''.join([h[i] for i in range(b/8,b/4)]) + m)
  R = scalarmult(B,r)
  S = (r + Hint(encodepoint(R) + pk + m) * a) % l
  return encodepoint(R) + encodeint(S)

def isoncurve(P):
  x = P[0]
  y = P[1]
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

def decodeint(s):
  return sum(2**i * bit(s,i) for i in range(0,b))

def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  #if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P


def decodepointcheck(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  #print("actually checking if it's on curve!")
  if not isoncurve(P): 
      #print("not on curve")
      quit() 
      raise Exception("decoding point that is not on curve")
  return P


def checkvalid(s,m,pk):
  if len(s) != b/4: 
    raise Exception("signature length is wrong")
    return False
  if len(pk) != b/8: 
    raise Exception("public-key length is wrong")
    return False
  R = decodepoint(s[0:b/8])
  A = decodepoint(pk)
  S = decodeint(s[b/8:b/4])
  h = Hint(encodepoint(R) + pk + m)
  if scalarmult(B,S) != edwards(R,scalarmult(A,h)):
    raise Exception("signature does not pass verification")
    return False
  return True
