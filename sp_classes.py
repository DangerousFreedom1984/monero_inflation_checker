import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector,hash_to_point,hash_to_scalar,random_scalar,cn_fast_hash
import misc_func
import copy
import varint_mic as varint
import pyblake2
import nacl.bindings
from enum import Enum

class grootle_proof:
    def __init__(self,m,n):
        self.A = Scalar(0)*dumber25519.G
        self.B = Scalar(0)*dumber25519.G
        self.f = misc_func.scalar_matrix(m,n-1,0)
        self.X = misc_func.point_matrix(m,0,0)
        self.zA = Scalar(0) 
        self.z = Scalar(0)


class sp_generators:
    def __init__(self,max_generators = 256):
        self.Gen = PointVector([])
        for i in range(max_generators):
            domain = str("sp_generator_factory") + str(i)
            self.Gen.append(hash_to_point(nacl.bindings.crypto_generichash_blake2b_salt_personal(domain.encode('ascii')).hex()))


    def at_index(self,index):
        return self.Gen[index]


class composition_proof:
    def __init__(self):
        self.c = Scalar(0)
        self.r_t1 = Scalar(0)
        self.r_t2 = Scalar(0)
        self.r_ki = Scalar(0)
        self.K_t1 = Scalar(0)*dumber25519.G

class transcript_flag(Enum):
        EXTERNAL_PREDICATE_CALL = 0
        UNSIGNED_INTEGER = 1
        SIGNED_INTEGER = 2
        BYTE_BUFFER = 3
        NAMED_CONTAINER = 4
        NAMED_CONTAINER_TERMINATOR = 5
        LIST_TYPE_CONTAINER = 6
        TRANSCRIPT_CLONE = 7

class transcript:
    def __init__(self,initial_str=''):
        self.bytevec = bytearray.fromhex(initial_str.encode('utf8').hex())

    def append_label(self,label):
        self.bytevec.append(3)
        self.bytevec.append(len(label))
        [self.bytevec.append(ord(x)) for x in label]

    def append_label_value(self,label, value):
        self.bytevec.append(3)
        self.bytevec.append(len(label))
        [self.bytevec.append(ord(x)) for x in label]
        self.bytevec.append(3)
        self.bytevec.append(int(len(value)/2))
        self.bytevec = bytearray.fromhex(self.bytevec.hex()+value)

    def get(self):
        return self.bytevec
        







