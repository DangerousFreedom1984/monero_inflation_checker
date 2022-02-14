########################################################################
#     MiniNero.py
#A miniature, commented
#port of CryptoNote and 
#Monero: 
#     crypto.cpp / crypto-ops.cpp
#
#Using Bernstein's ed25519.py for the curve stuff.
#The main point is to have a model what's happening in CryptoNote
#             -Shen.Noether
#
#Note: The ring image function seems
# to take a lot of memory to run
# it will throw strange errors if
# your computer doesn't have 
# enough
#Note2: 
# As of yet, slightly incompatible, although mathematically equivalent.
# The discrepancies are some differences in packing and hashing.
#
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/
#
#The parts of code from Bernstein(?)'s library possibly has it's own license
# which you can dig up from http://cr.yp.to/djb.html
########################################################################

#"MiniNero" by Shen Noether mrl. Use at your own risk.
import hashlib #for signatures
import math
import Crypto.Random.random as rand
import Keccak #cn_fast_hash
# import mnemonic #making 25 word mnemonic to remember your keys
import binascii #conversion between hex, int, and binary. Also for the crc32 thing
# import ed25519 #Bernsteins python ed25519 code from cr.yp.to
#import ed25519ietf # https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
import zlib
import sys
from dumb25519 import Scalar, Point, PointVector
import dumb25519
import secrets
import struct
from Crypto.Util import number


sys.setrecursionlimit(10000)


#//////////////////////////////////////////////////////////////




def scalarmultBase(sk):
    #returns pubkey in hex, expects hex sk
    return public_key(sk)

def ge_frombytes_vartime(img):
    return 0

def public_key(sk):
    #Input: Scalar (secret key)
    #Output: Point (Public key)
    pk = sk * dumb25519.G
    return pk


def hexToInt(h):
    # Input: String with hex value
    # Output: Int value corresponding
    # Conversion uses little indian. The function int(h,16) wont work as it uses big indian.
    return int.from_bytes(bytes.fromhex(h), "little")

    # return sum(2**i * ed25519.bit(s,i) for i in range(0,bb)) #does to int

# def intToHex(i):
    # # import ipdb;ipdb.set_trace()
    # print('int to hex: ')
    # print(ed25519.encodeint(i))
    # print(binascii.hexlify(ed25519.encodeint(i)))
    # return binascii.hexlify(ed25519.encodeint(i)) #hexlify does bytes to hex


# def hexToInt(h):
    # s = binascii.unhexlify(h) #does hex to bytes
    # bb = len(h) * 4 #I guess 8 bits / b
    # return sum(2**i * ed25519.bit(s,i) for i in range(0,bb)) #does to int

# def intToHex(i):
    # return binascii.hexlify(ed25519.encodeint(i)) #hexlify does bytes to hex



def publicFromSecret(sk):
    #returns pubkey in hex, same as scalarmultBase
    return binascii.hexlify(public_key(hexToInt(sk)))
#////////////////////////////////////////////// Functions for hashToPointCN
# Base field Z_p
p = 2**255 - 19




def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    #Function dumb25519.make_point(y) is wrong
    return dumb25519.Point(x,y)

def cn_fast_hash(s):
    # import sha3
    # # import ipdb;ipdb.set_trace()
    # k = sha3.keccak_256()
    # k.update(s.encode())
    # print('sha3: ')
    # print(k.hexdigest())

    k = Keccak.Keccak()
    return k.Keccak((len(s) * 4, s), 1088, 512, 32 * 8, False).lower() #r = bitrate = 1088, c = capacity, n = output length in bits


def sqroot(xx):
  x = expmod(xx,((q+3)//8),q)
  if (x*x - xx) % q != 0: 
    x = (x*I) % q
  if (x*x - xx) % q != 0: 
    print("no square root!")
  return x

def theD():
    return d

def computeA():
  return 2 *((1 - d) % q) * inv((1 + d) % q) % q

def expmod(b,e,m):
    return pow(b,e,m)

def modp_inv(x):
    return pow(x, p-2, p)

def inv(x):
  return pow(x,q-2,q)

#//////////////////////////////////////////////
def hashToPointCN(hexVal):
    u= hexToInt(cn_fast_hash(hexVal)) % q
    A = 486662
    ma = -1 * A % q
    ma2 = -1 * A * A % q
    sqrtm1 = sqroot(-1)
    d = theD() #print(radix255(d))
    fffb1 = -1 * sqroot(-2 * A * (A + 2) )
    #print("fffb1", ed25519.radix255(fffb1))
    fffb2 = -1 * sqroot(2 * A * (A + 2) )
    #print("fffb2", ed25519.radix255(fffb2))
    fffb3 = sqroot( -1 * sqrtm1 * A * (A + 2))
    #print("fffb3", ed25519.radix255(fffb3))
    fffb4 = -1 * sqroot( sqrtm1 * A * (A + 2))
    #print("fffb4", ed25519.radix255(fffb4))

    w = (2 * u * u + 1) % q
    xp = (w *  w - 2 * A * A * u * u) % q

    rx = expmod(w * inv(xp),((q+3)//8),q) 

    x = rx * rx * (w * w - 2 * A * A * u * u) % q

    y = (2 * u * u  + 1 - x) % q #w - x, if y is zero, then x = w

    negative = False
    if (y != 0):
        y = (w + x) % q #checking if you got the negative square root.
        if (y != 0) :
            negative = True
        else :
            rx = rx * -1 * sqroot(-2 * A * (A + 2) ) % q
            negative = False
    else :
        #y was 0..
        rx = (rx * -1 * sqroot(2 * A * (A + 2) ) ) % q 
    if not negative:
        rx = (rx * u) % q
        z = (-2 * A * u * u)  % q
        sign = 0
    else:
        z = -1 * A
        x = x * sqrtm1 % q #..
        y = (w - x) % q 
        if (y != 0) :
            rx = rx * sqroot( -1 * sqrtm1 * A * (A + 2)) % q
        else :
            rx = rx * -1 * sqroot( sqrtm1 * A * (A + 2)) % q
        sign = 1
    #setsign
    if ( (rx % 2) != sign ):
        rx =  - (rx) % q 
    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q

    P = point_compress([rx, ry, rz])
    P8 = P * Scalar(8)  
    return P8


def hash_to_scalar(data):
    res = cn_fast_hash(data)
    return sc_reduce32(res)

def sc_reduce32(data):
    return Scalar(hexToInt(data) % l)


def generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index):
    #returns a ring signature
    if sec_index >= pubs_count:
        print("bad index of secret key!")
        quit()
    # Maybe other checks?

    summ = Scalar(0)
    aba = [Scalar(0) for xx in range(pubs_count)] 
    abb = [Scalar(0) for xx in range(pubs_count)] 
    sigc = [Scalar(0) for xx in range(pubs_count)] #these are the c[i]'s from the whitepaper
    sigr =[Scalar(0) for xx in range(pubs_count)] #these are the r[i]'s from the whitepaper
    for ii in range(0, pubs_count):
        if (ii == sec_index):
            kk = dumb25519.random_scalar()
            # kk = int('11b08c50a56c4d4c167488653ff7ef1f578d032fdcd723ed5aa2d64324a04e05',16)
            # import ipdb;ipdb.set_trace()
            # Printing k after: 11b08c50a56c4d4c167488653ff7ef1f578d032fdcd723ed5aa2d64324a04e05
            # Printing tmp3 : 6ae54b266532a0e9a09a9f2de55318d4eb2ec54cadfa4194613d369d517ba6a4
            print('prefix: ')
            print(prefix)

            kk1 = Scalar('57046e2d1a2088d0b9613c3b87d8530e5184da563a99cf700b45b146bbd73f0c')
            tmp3 = scalarmultBase(kk1) #L[i] for i = s
            # Random Public key
            aba[ii] = tmp3
            print('aba: ')
            print(tmp3)
            # tmp4 = dumb25519.hash_to_point2(pubs) #R[i] for i = s
            tmp4 = hashToPointCN(str(pubs[ii]))
            print('after hashtopoint: ')
            print(tmp4)
            abb[ii] = kk1 * tmp4 
            print('abb: ')
            print(abb[ii])
        else:
            k1 = dumb25519.random_scalar()
            k2 = dumb25519.random_scalar()
            if ge_frombytes_vartime(pubs[ii]) != 0:
                print("error in ring sig!!!")
                quit()
            tmp2 = ge_double_scalarmult_base_vartime(k1, pubs[ii], k2) #this is L[i] for i != s
            aba[ii] = tmp2
            tmp3 = hash_to_ec(pubs[ii])
            abb[ii] = ge_double_scalarmult_vartime(k2, tmp3, k1, image) #R[i] for i != s
            sigc[ii] = k1  #the random c[i] for i != s
            sigr[ii] = k2  #the random r[i] for i != s
            summ = sc_add(summ, sigc[ii]) #summing the c[i] to get the c[s] via page 9 whitepaper
    
    buf = struct.pack('64s', prefix)
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', str(aba[ii]).encode())
        buf += struct.pack('64s', str(abb[ii]).encode())


    #hh is Scalar
    hh = hash_to_scalar(buf.decode())
    
    # import ipdb;ipdb.set_trace()

    sigc[sec_index] = sc_sub(hh, summ) # c[s] = hash - sum c[i] mod l
    sigr[sec_index] = sc_mulsub(sigc[sec_index], sec, kk1) # r[s] = q[s] - sec * c[index]

    print('sigc: ')
    print(sigc)

    print('sigr: ')
    print(sigr)
    return image, sigc, sigr


            
     


def check_ring_signature(prefix, key_image, pubs, pubs_count, sigr, sigc):
    #from https://github.com/monero-project/bitmonero/blob/6a70de32bf872d97f9eebc7564f1ee41ff149c36/src/crypto/crypto.cpp
    #this is the "ver" algorithm
    aba = [0 for xx in range(pubs_count)] 
    abb = [0 for xx in range(pubs_count)] 

    if ge_frombytes_vartime(key_image) != 0:
        print("ring image error in checking sigs")
        quit()
    summ = 0
    buf = struct.pack('64s', prefix)
    for ii in range(0, pubs_count):
        if ((sc_check(sigc[ii]) != 0) or (sc_check(sigr[ii]) != 0)):
            print("failed sc_check in check ring sigs")
            quit()
        if ge_frombytes_vartime(pubs[ii]) != 0:
            print("public key is a bad point in ring sigs")
            quit()

        tmp2 = ge_double_scalarmult_base_vartime(sigc[ii], pubs[ii], sigr[ii]) 
        aba[ii] = tmp2
        tmp3 = hash_to_ec(pubs[ii])
        tmp2 = ge_double_scalarmult_vartime(sigr[ii], tmp3, sigc[ii], key_image)
        abb[ii] = tmp2
        summ = sc_add(summ, sigc[ii])
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', aba[ii])
        buf += struct.pack('64s', abb[ii])
    
    hh = hash_to_scalar(buf,len(buf))
    hh = sc_sub(hh, summ)
    return sc_isnonzero(hh) == 0


def sc_add(aa, bb):
    return (aa + bb ) % q
def sc_sub(aa, bb):
    return (aa - bb ) % q

def sc_isnonzero(c):
    return (c % q!= 0 )

def sc_mulsub(aa, bb, cc):
    return (cc - aa * bb ) % l


# def hexToLong(a):
    # print('hex to long before: ')
    # print('type a: ')
    # print(type(a))
    # print('a: ')
    # print(a)
    # print('return 1: ')
    # # print(number.long_to_bytes(a).encode("hex"))
    # print(number.bytes_to_long(binascii.unhexlify(a)))
    # return number.bytes_to_long(binascii.unhexlify(a))
    # # return number.bytes_to_long(a.decode("hex"))

# def longToHex(a):
    # print('long to hex before: ')
    # print('type a: ')
    # print(type(a))
    # print('a: ')
    # print(a)
    # print('return 1: ')
    # # print(number.long_to_bytes(a).encode("hex"))
    # print(binascii.hexlify(number.long_to_bytes(a)))

    # # return number.long_to_bytes(a).encode("hex")
    # return binascii.hexlify(number.long_to_bytes(a))

# def hexToBits(a):
    # # return a.decode("hex")
    # return binascii.unhexlify(a)

# def bitsToHex(a):
    # return binascii.hexlify(a)
    # # return a.encode("hex")

# def sc_check(key):
    # #in other words, keys which are too small are rejected
    # return 0 
    # #s0, s1, s2, s3, s4, s5, s6, s7 = load_4(longToHex(key))
    # #return (signum_(1559614444 - s0) + (signum_(1477600026 - s1) << 1) + (signum_(2734136534 - s2) << 2) + (signum_(350157278 - s3) << 3) + (signum_(-s4) << 4) + (signum_(-s5) << 5) + (signum_(-s6) << 6) + (signum_(268435456 - s7) << 7)) >> 8

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

d = -121665 * inv(121666)
I = expmod(2,((q-1)//4),q)

if __name__ == "__main__":
    # if sys.argv[1] == "fasthash":
        # mysecret = "99b66345829d8c05041eea1ba1ed5b2984c3e5ec7a756ef053473c7f22b49f14"
        # output_index = 2
        # buf2 = struct.pack('64sl', mysecret, output_index) 
        # #buf2 = pickle(buf)
        # #print(buf2)
        # print(buf2)
        # print(cn_fast_hash(mysecret, len(mysecret)))
        # print(cn_fast_hash(buf2, len(buf2)))
 
    # if sys.argv[1] == "hashscalar":
        # data = "ILOVECATS"
        # print(cn_fast_hash(data, len(data)))
        # print(hash_to_scalar(data, len(data)))
    # if sys.argv[1] == "hashcurve":
        # data = "ILOVECATS"
        # print(cn_fast_hash(data, len(data)))
        # print(hash_to_ec(data))

    # if sys.argv[1] == "ringsig":
        # #these are fixed since my computer runs out of memory
        # xa = 54592381732429499113512315392038591381134951436395595620076310715410049314218
        # Pa = "3c853b5a82912313b179e40d655003c5e3112c041fcf755c3f09d2a8c64d9062"
        # xb = 14662008266461539177776197088974240017016792645044069572180060425138978088469
        # Pb = "1d0ecd1758a685d88b39567f491bc93129f59c7dae7182bddc4e6f5ad38ba462"
        # ima = "0620b888780351a3029dfbf1a5c45a89816f118aa63fa807d51b959cb3c5efc9"
        # ima, sic, sir = generate_ring_signature("dest", ima, [Pa, Pb],2,  xb, 1)

        # print("ima",ima)
        # print("sic", sir)
        # print("sir", sic)
        # print(check_ring_signature("dest", ima, [Pa, Pb], 2, sir, sic))

    # if sys.argv[1] == "conv":
        # #testing reduction
        # a = "99b66345829d8c05041eea1ba1ed5b2984c3e5ec7a756ef053473c7f22b49f14"
        # print(a)
        # r = hexToLong(a)
        # print(r)
        # a = longToHex(r)
        # print(a)
    # if sys.argv[1] == "red":
        # a = "99b66345829d8c05041eea1ba1ed5b2984c3e5ec7a756ef053473c7f22b49f14"
        # tmp = rand.getrandbits(64 * 8)
        # tmp2 = longToHex(tmp)
        # print(tmp2)
        # tmp3 = longToHex(sc_reduce(tmp))
        # print(tmp3)
        # tmp4 = sc_reduce32(CURVE_P + 1)
        # print(tmp4)
        # tmp5 = sc_reduce(CURVE_P + 1)
        # print(tmp5)
    # if sys.argv[1] == "gedb":
        # x, P = generate_keys()
        # print(ge_double_scalarmult_base_vartime(x, P, x))
    # if sys.argv[1] == "sck":
        # #testing sc_check
        # x, P = generate_keys()
        # print(sc_check(x))
        # print("nonreduced", longToHex(x))
        # print("reduced", sc_reduce32_2(x))
        # print("check reduced", sc_check(hexToLong(sc_reduce32_2(x))))
    
    if sys.argv[1] == "gen_ring_sig":
        #these are fixed since my computer runs out of memory
        xa = 54592381732429499113512315392038591381134951436395595620076310715410049314218
        Pa = "3c853b5a82912313b179e40d655003c5e3112c041fcf755c3f09d2a8c64d9062"
        xb = 14662008266461539177776197088974240017016792645044069572180060425138978088469
        Pb = "1d0ecd1758a685d88b39567f491bc93129f59c7dae7182bddc4e6f5ad38ba462"
        ima = "0620b888780351a3029dfbf1a5c45a89816f118aa63fa807d51b959cb3c5efc9"

        # prefix = b"afb7f48535b7e9245fe0a95b207c4eacd1487fda4044ff7164ca52c8de288223"
        # image = "e463651cbb5e32b0175a91ce3048b48b7101e76ea4489dc896f7b218fd3c2c68" 
        # pubs = "d23ef3f9c7689f9af22a1aaa555881376ccc0188b98f95f2560f57a36a6d7377"
        # pubs_count = 1
        # sec = "7012c58dd77b753fec6c03248bdf67af6a4d17dcaad64f9588bc583c59e28f09"
        # sec_index = 0


        prefix = b"8ae47e12cca160c1a52e5517f6f1822d2bb6f1a24e8094b78891458f2b3e4d5d"
        image = "f1206393161213a5e4093f9c65e6ef92ca7f21b3513c90e50422e1280ca8165b" 
        pubs_array = [Point('649f27680aa9cbfb1166d5ad0dd80d20508646442e3e850c0a772a13a4c6b14a')]
        pubs = PointVector(pubs_array)
        pubs_count = 1
        sec = Scalar("568325b113beabab5b8a1643b065f4bae5181c7b2026ea8dfefeff118ba6de0d")
        sec_index = 0
        # Pub keys count: The value of a : 1
# Public key of ring: 4e4a0c5148bab2d72c78838fa89751f4db9b4415b4d42de257e629728fba045f
# Secret key of ring: 4daf994d9b2b553b70870151b6d69421826a0e10811db035004b6c2955801e0c
# Key image: fd8c852f70194d4b3a49c7a1d14940d179d6839e1d6e72c6520446e245cc141b
# Hash prefix: 5cbb7b08eeae7a975d3b77387bb3b2f6454ec949dfb0bd4b987e98ca83f3a72f


        ima, sic, sir = generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index)

        print("ima",ima)
        print("sic", sir)
        print("sir", sic)
        # print(check_ring_signature("dest", ima, [Pa, Pb], 2, sir, sic))
        import ipdb;ipdb.set_trace()

        


        
        

