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

class Transaction_prefix:
    def __init__(self,version,unlock_time,qty_input,vin,qty_output,vout,size_extra,extra):
        self.version = version
        self.unlock_time = unlock_time
        self.qty_input = qty_input
        # self.prefix_vin = prefix_vin
        self.vin = vin
        # self.amount_vin = amount_vin
        # self.qty_offsets = qty_offsets
        # self.offsets = offsets
        # self.vin_ki = vin_ki
        self.qty_output = qty_output
        # self.amount_vout = amount_vout
        # self.vout_ki = vout_ki
        self.vout = vout
        self.size_extra = size_extra
        self.extra = extra

### Implement tx_prefix_hash

# version = 1
# unlock_time = 0
# qty_input = 3
    # prefix_vin = 2
    # amount_vin = 
    #   qty_offsets = 4
    #   offsets 
    # vin_key_image
# qty_output = 3
    # amount
    # vout_key_image
# size_extra
# extra

    def get_serialized_tx_prefix(self):
        serial = ''
        serial += to_varint(self.version)
        serial += to_varint(self.unlock_time)
        serial += to_varint(self.qty_input)
        # prefix_vin_v,amount_vin_v,offsets_v, vin_ki = [],[],[],[]
        for i in range(int(self.qty_input)):
            serial += to_varint(2) #prefix
            serial += to_varint(self.vin[i]["key"]["amount"])
            for j in range(len(self.vin[0]["key"]["key_offsets"])):
                serial += to_varint(self.vin[i]["key"]["key_offsets"][j])
                print(self.vin[i]["key"]["key_offsets"][j])
            serial += self.vin[i]["key"]["k_image"]
        serial += to_varint(self.qty_output)
        for i in range(int(self.qty_output)):
            serial += to_varint(2) #prefix
            serial += to_varint(self.vout[i]["amount"])
            serial += self.vout[i]['target']["key"]
        serial += to_varint(self.size_extra)
        for i in range(self.size_extra):
            serial += format(self.extra[i],'x')
            print(self.extra[i])
        return serial



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

def ge_double_scalarmult_base_vartime(aa, AA, bb):
    #a very nice comment in the CN code for this one!
    #r = a * A + b * B
    #where a = a[0]+256*a[1]+...+256^31 a[31].
    #and b = b[0]+256*b[1]+...+256^31 b[31].
    #B is the Ed25519 base point (x,4/5) with x positive.
    #cf also https://godoc.org/github.com/agl/ed25519/edwards25519

    tmpa = aa*AA
    tmpb = bb*dumb25519.G
    return tmpa+tmpb
    # tmpa = ge_scalarmult(aa, AA)
    # tmpb = ge_scalarmult(bb, BASEPOINT)
    # return toHex(edwards(toPoint(tmpa), toPoint(tmpb)))

def ge_double_scalarmult_vartime(aa, AA, bb, BB):
    #a very nice comment in the CN code for this one!
    #r = a * A + b * B
    #where a = a[0]+256*a[1]+...+256^31 a[31].
    #and b = b[0]+256*b[1]+...+256^31 b[31].
    #B is the Ed25519 base point (x,4/5) with x positive.
    #cf also https://godoc.org/github.com/agl/ed25519/edwards25519
    tmpa = aa*AA
    tmpb = bb*BB
    return tmpa+tmpb
    # tmpa = ge_scalarmult(aa, AA)
    # tmpb = ge_scalarmult(bb, BB)
    # return toHex(edwards(toPoint(tmpa), toPoint(tmpb)))

# def ge_scalarmult(a, A):
    # return encodepoint(scalarmult(toPoint(A), a)).encode("hex") # now using the eddie function

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
            print('prefix: ')
            print(prefix)

            kk = Scalar('7230889c49bd4b1937ced6fb631262c55a5c00aa2dde81915e1d9ea40fa59400')
            tmp3 = scalarmultBase(kk) #L[i] for i = s
            # Random Public key
            aba[ii] = tmp3
            print('aba: ')
            print(tmp3)
            # tmp4 = dumb25519.hash_to_point2(pubs) #R[i] for i = s
            tmp4 = hashToPointCN(str(pubs[ii]))
            print('after hashtopoint: ')
            print(tmp4)
            abb[ii] = kk * tmp4 
            print('abb: ')
            print(abb[ii])
        else:
            k1 = dumb25519.random_scalar()
            k2 = dumb25519.random_scalar()
            k1 = Scalar('0a35abab100a2b356d0df75eb5b81ec3947ed7d3d7a125964e4ba22604559f0c')
            k2 = Scalar('31772e5d0a409293d538a986e43503f6781a98247de0601ffbeacf6e803d7308')
            # if ge_frombytes_vartime(pubs[ii]) != 0:
                # print("error in ring sig!!!")
                # quit()
            tmp2 = ge_double_scalarmult_base_vartime(k1, pubs[ii], k2) #this is L[i] for i != s
            print('aba: ')
            print(tmp2)
            aba[ii] = tmp2
            tmp3 = hashToPointCN(str(pubs[ii]))
            print('tmp3: ')
            print(tmp3)
            abb[ii] = ge_double_scalarmult_vartime(k2, tmp3, k1, Point(image)) #R[i] for i != s
            print('abb: ')
            print(abb[ii])
            sigc[ii] = k1  #the random c[i] for i != s
            sigr[ii] = k2  #the random r[i] for i != s
            summ = sc_add(summ, sigc[ii]) #summing the c[i] to get the c[s] via page 9 whitepaper
    
    buf = struct.pack('64s', str(prefix))
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', str(aba[ii]).encode())
        buf += struct.pack('64s', str(abb[ii]).encode())


    #hh is Scalar
    print('buf: ')
    print(buf)
    c = hash_to_scalar(buf.decode())
    
    # import ipdb;ipdb.set_trace()

    sigc[sec_index] = sc_sub(c, summ) # c[s] = hash - sum c[i] mod l
    sigr[sec_index] = sc_mulsub(sigc[sec_index], sec, kk) # r[s] = q[s] - sec * c[index]

    print('sigc: ')
    print(sigc)

    print('sigr: ')
    print(sigr)
    return image, sigc, sigr


            
     


def check_ring_signature(prefix, key_image, pubs, pubs_count, sigr, sigc):
    #from https://github.com/monero-project/bitmonero/blob/6a70de32bf872d97f9eebc7564f1ee41ff149c36/src/crypto/crypto.cpp
    #this is the "ver" algorithm
    aba = [Scalar(0) for xx in range(pubs_count)] 
    abb = [Scalar(0) for xx in range(pubs_count)] 

    summ = Scalar(0)
    for ii in range(0, pubs_count):
        
        aba[ii] = ge_double_scalarmult_base_vartime(sigc[ii], pubs[ii], sigr[ii]) 
        tmp3 = hashToPointCN(str(pubs[ii]))
        # print('tmp3: ')
        # print(tmp3)
        abb[ii] = ge_double_scalarmult_vartime(sigr[ii], tmp3, sigc[ii], Point(key_image)) 
        summ = sc_add(summ, sigc[ii])
        # print('Sum: ')
        # print(summ)

    buf = struct.pack('64s', prefix)
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', str(aba[ii]).encode())
        buf += struct.pack('64s', str(abb[ii]).encode())

    hh = hash_to_scalar(buf.decode())
    hh = sc_sub(hh, summ)
    print('Sub: ')
    print(hh)
    # import ipdb;ipdb.set_trace()

    return sc_isnonzero(hh) == 0


def sc_add(aa, bb):
    return (aa + bb ) % l

def sc_sub(aa, bb):
    return (aa - bb ) % l

def sc_isnonzero(c):
    return (c % q != Scalar(0) )

def sc_mulsub(aa, bb, cc):
    return (cc - aa * bb ) % l


def sc_check(a):
    if a == Scalar(0):
        return False
    return (a == sc_reduce_key(a))

def sc_reduce_key(a):
    return a % l

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

d = -121665 * inv(121666)
I = expmod(2,((q-1)//4),q)

if __name__ == "__main__":
    
    if sys.argv[1] == "gen_ring_sig":

        prefix = b"8ae47e12cca160c1a52e5517f6f1822d2bb6f1a24e8094b78891458f2b3e4d5d"
        image = "f1206393161213a5e4093f9c65e6ef92ca7f21b3513c90e50422e1280ca8165b" 
        pubs_array = [Point('649f27680aa9cbfb1166d5ad0dd80d20508646442e3e850c0a772a13a4c6b14a')]
        pubs = PointVector(pubs_array)
        pubs_count = 1
        sec = Scalar("568325b113beabab5b8a1643b065f4bae5181c7b2026ea8dfefeff118ba6de0d")
        sec_index = 0

        ima, sic, sir = generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index)

        print("ima",ima)
        print("sic", sir)
        print("sir", sic)
        # print(check_ring_signature("dest", ima, [Pa, Pb], 2, sir, sic))
    if sys.argv[1] == "gen_ring_sig_mult":

        prefix = b'7f658119722803b0fdab41843d4c3c2510e1cbbe64746255dfbd93b48a380856'
        image = 'e525d54d017780fd439141cf9ec25ffeecdc6a2cb7b60c332c93740b3834bd8e' 
        pubs_array = [Point('a9e8410fbdee927953160354801f281845e00f8cdd476b5012195854f6d1dfeb'),Point('b4493a0bbb5b9968685202619eff663dbc7f95d6baec74b229fbb935d9e88610')]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)
        sec = Scalar('ef0338f3ab4d27b137aa5d82b481e7e1b942f513b1faa8cbbdca8bacadb6bb09')
        sec_index = 0

        ima, sic, sir = generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index)

        print("ima",ima)
        print("sic", sir)
        print("sir", sic)

        import ipdb;ipdb.set_trace()




    if sys.argv[1] == "check_ring_sig":

        prefix = b'ad19333d6a1e36907f47d2f37904f9fa17557661ff3ff6f3c3207785050e9b59'
        image = '52e8e81fe928a338b92dadfff62baa93055ec82d3891108c8e0a21d2db4316c4' 
        # image = 'a855ad897cb46e3e772143e33f1c8cf548ef4139cabab101db673cebe9e27ddc'
        pubs_array = [Point('d0a86250c342d8cbcf528fcff880defe0a8116ba5e2db4cfe1aea4dd7102e934'),Point('1623db2b826c4b3753d91a91af9542e6b7f3d8d674eefa0c6e9261b9e5867dbe')]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)

        # image = 'bef6ac005f9a6400ac391203862c97fff800ddff5acb3aff77ff7dff65db34ff8d990e0110b5c201963bb5ffb3509401862dda00c4ce020168a8fb009cf96affdddc030093cb77ff0f507effb6e0080001000000000000000000000000000000000000000000000000000000000000000000000000000000f52742fe1808fdff145225fff3b1c8ff4b696101d3f654009864d3fe44ea6800c491f7ff5b20adff7180c3ffff3c57ff32592cffb68d5bffa711d201b2c8b900b7ce4103ae5659fe5a4d3901d72b2100dbf602036716d9fec40a82fdb4adc4008fe8b90090dc560061220e00d08a42005c04fbfe75b04901f2815efecbcac9ffe35a8f01c487b0ffca29ebfe38538cffc9706101986cb000f68117feef834bffc012dffe87a955ff690284007afe81ffbfa973002937e0ff2088e700b15985ffd465ab01966fefff9fbd8cfe58093a0155bfe300b968a10051c8b5006be77900e6f581fca0c93001c2145303a5b4c4ffa5b12bfeca5b3d002f5a4200b76f8000031cc9023b24fafe50141400485aafff708befffe7f6e8ff869d56ff8354e8fff88d42ff8c42aaff5721f50052c3d700a8372200aaf80fff238022016d495d007420a3fee0075900aa0e8c014dd7b900fbb854feab6133ffbc87e8000d9e72ffc24a1aff827ac0000f1e550044992900c7b4a0fffc6c2dff458fd1ffad71480085ee4701457a77fff49c3a01989b0e0075ad3d01dea1ad011b0ed5ff2243e300db8ba5031fef6eff5f66bcfe2f547500e0f0f700c21e1efed92a1200aafdd9003fcd3301b5dec300c6a1a7006f168800c1312b011ad435ff064a4bfe3579db00543959ffdbd61b00e19764ff452f76000fe182000cc12200408cbb00d46f9eff46531bfee67f1c00daf50efe12ebd1ffa62471015590dafeedd7b00266ee1500cebcb1ff419d310169fe2f016f257e004e1fdbfeb22add0072c72f01f38772ff77ee2b00bc50d2ffc2b5ad00b33572008f3714ff410c4400583905fec2781500d7c3d9ff8c6259ff7cb01bfe64a76400fd77aaff0abee1ff9d7b33fe4d2e3400f7db00ff922d52005ebd00fe3eb468ffa64526fe153b7e006d9e1d01f29c310024c5e2fe26905a003348c1fed4484f0170f520006c1d68fe1a5dca01d4522a01b1bd36fffd734601084e5cff0c9d5b0165e012fe88438dff68b6a80068bd4700009dc501f01334ff4b68d6fccfeda1ff50049e01c2142c00e5a9ddff0c0a2200a80056fff37926ff3884fe003301c0ffe861bbff7f268500c9e6a0002842e0005ad9a70078a12bffc1d9fd01326d55ff2a5c31ffa8d76d00271789fee4e8490080c78cfe6a56f0ff9ca1c100b09bdb0064d8dd011db38dff43af7703408ce6fea68907ff4f98510018e053fc65219aff300e25fd60db68fffe5506007b7f1bffab75430034cc68ff12f97ffd817667ffc0b40400d54d830081a8de002587cc00e6db6401d5c0bbff7a4170fe77ca5300752954fe795e6efffca500fe01e2750096f4fefe3a4ea4006904bb01ea54e1ff14785fffe17c8100780f4c00da82b6006399290123246affb88c7d01e47d6c0021ec03fe498e3b00d2928aff2e4765ffa2d9ef009d586cff35247703a0114dffbcd992004472470109c29b00f163fa003247d401a8be6c0000bea3feed241d0185f616003eefa3ffdb347500fe743200c3d04effc86735ff4d951801a43512ffdd40e0fed2e7a3ff7c9c18ffdfea380025fac3fe74aec10077edb201e0d5ccff3a7ef1005ad2890075acdd00a28cb40025e0ee01df76ff00'


        sc = [Scalar('2d87a80cf708e6d23b7038b3854d98f4a95ec50647b9e05ef7ad2665c0910d0a'), Scalar('0a8b8b3849e3e5d6bf712f263d94f00bbf6abe5ef5f00192e91c83f3461d660f')]
        sr = [Scalar('d9697f46b2430cbcbe5a2fc18e0e4c7364c92d90e43e7903bf32eb58c4d4010c'), Scalar('bd20e7ec116ec1ab3c3edd0dd003fbfe3e51f1edc66b6061ab6bd0489d86aa09')]

        sigc = dumb25519.ScalarVector(sc)
        sigr = dumb25519.ScalarVector(sr)

        result = check_ring_signature(prefix, image, pubs, pubs_count, sigr, sigc)
        
        print("sic", sigr)
        print("sir", sigc)
        print('Verified: ')
        print(result)

        import ipdb;ipdb.set_trace()

        


        
        

