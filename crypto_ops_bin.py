import nacl.bindings
from df25519 import (
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
import df25519
import ipdb;
import time
import binascii
import varint_mic as varint



# sk = df25519.random_scalar()

# r1 = dumber25519.Scalar('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')

# skb = bytes.fromhex('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')

str_hex = '21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00'

rb = df25519.Scalar(str_hex)

domain = str("bulletproof")
Pi = hash_to_point(cn_fast_hash(str(df25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(4)))
# Hi = Point()

t1 = time.time()
rb = df25519.Scalar('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')
P = df25519.Scalar(8)*df25519.G
t2 = time.time()
print("Total time 1 mult: " + str(t2-t1))

ipdb.set_trace()


