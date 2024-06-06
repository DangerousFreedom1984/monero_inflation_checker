import nacl.bindings

from dumber25519 import (
    Scalar,
    Point,
    ScalarVector,
    PointVector,
    random_scalar,
    random_point,
    hash_to_scalar,
    hash_to_point,
    cn_fast_hash,
)
import dumber25519
import dumber25519
import ipdb;
import time
import binascii
import struct
import varint_mic as varint

XG = dumber25519.Gx
# int_converted_byte = struct.pack('>I', XG)


sk = dumber25519.random_scalar()

r1 = dumber25519.Scalar('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')

skb = bytes.fromhex('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')

t1 = time.time()
rb = dumber25519.Scalar('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')
P = rb * dumber25519.G
t2 = time.time()
print("Total time 1 mult: " + str(t2-t1))

print(P)

domain = str("bulletproof")
Pi = hash_to_point(cn_fast_hash(str(dumber25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(4)))

tcv1 = time.time()
G_bytes = bytes.fromhex(str(dumber25519.G))
tcv2 = time.time()
print("Time to convert to binary: " + str((tcv2-tcv1)*10**3))

ta1 = time.time()
for i in range(1000):
    added = r1 + sk
ta2 = time.time()
print("Time to add: " + str((ta2-ta1)))



ti = time.time()
# for i in range(1000):
Q = nacl.bindings.crypto_scalarmult_ed25519_noclamp(skb, G_bytes)
tb = time.time()
# for i in range(1000):
B = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(skb)
tm = time.time()

print("Time using mult: "+str((tb-ti)*10**3) + str(" ms"))
print("Time using base mult: "+str((tm-tb)*10**3) + str( " ms"))

y = r1
P = dumber25519.G
tbin1 = time.time()
sk = binascii.a2b_hex(str(y).encode("utf-8"))
tbin2 = time.time()
print("Time to convert to binary using binascii: "+str((tbin2 - tbin1)*10**3) + str(" ms"))

# tbina1 = time.time()
# sk = nacl.encoding.binascii.a2b_hex(str(y).encode("utf-8"))
# tbina2 = time.time()
# print("Time to convert to binary using binascii nacl: "+str((tbina2 - tbina1)*10**3) + str(" ms"))

tenc1 = time.time()
encb = str(y).encode("utf-8")
tenc2 = time.time()
print("Time to encode: "+str((tenc2 - tenc1)*10**3) + str(" ms"))



ipdb.set_trace()