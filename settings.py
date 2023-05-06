"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import copy
from dumber25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point,cn_fast_hash
import dumber25519
import varint_mic as varint


def node_choice(choice):
    global node_conn
    global url_str 
    global Hi,Gi,Hi_plus,Gi_plus
    M,N = 16,64

    domain = str("bulletproof")
    Hi = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
    Gi = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

    domain_plus = str("bulletproof_plus")
    Hi_plus = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
    Gi_plus = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

    node_conn = copy.copy(choice)

    if node_conn == 0:
        url_str = 'http://node.sethforprivacy.com:18089/'
    else:
        url_str = 'http://localhost:18081/'
