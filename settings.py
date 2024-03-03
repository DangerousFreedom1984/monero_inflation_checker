"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import copy
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
import varint_mic as varint
import numpy as np


global url_str
global Hi, Gi, Hi_plus, Gi_plus

#url_str = "http://node.sethforprivacy.com:18089/"
url_str = "http://xmr-node.cakewallet.com:18081/"

Hi = PointVector(np.load("Hi.npy", allow_pickle=True))
Gi = PointVector(np.load("Gi.npy", allow_pickle=True))
Hi_plus = PointVector(np.load("Hi_plus.npy", allow_pickle=True))
Gi_plus = PointVector(np.load("Gi_plus.npy", allow_pickle=True))


def node_choice(choice):
    global node_conn, url_str

    node_conn = copy.copy(choice)

    if node_conn == 0:
        url_str = "http://node.sethforprivacy.com:18089/"
    else:
        url_str = "http://localhost:18081/"


# M,N = 16,64

# domain = str("bulletproof")
# Hi_old = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
# Gi_old = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

# domain_plus = str("bulletproof_plus")
# Hi_plus_old = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
# Gi_plus_old = PointVector([hash_to_point(cn_fast_hash(str(dumber25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])
