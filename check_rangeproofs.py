"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import json
#from varint import encode as to_varint
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector
import copy
import multiprocessing

def check_sig_Borromean(resp_json,sig_ind):
    P1,P2,bbee,bbs0,bbs1 = get_borromean_vars(resp_json,sig_ind)
    if not check_Borromean(P1,P2,bbee,bbs0,bbs1):
        print('Potential inflation in Borromean Signatures! Please verify what is happening!')
        raise Exception('borromean_signature_failure')
    return 0


def get_borromean_vars(resp_json,ind):
    Ci = resp_json["rctsig_prunable"]["rangeSigs"][ind]["Ci"]
    asig = resp_json["rctsig_prunable"]["rangeSigs"][ind]["asig"]
    P1,P2,bbee,bbs0,bbs1 = [],[],[],[],[]
    factors = len(asig)//64 - 1 #=128
    bbee = Scalar(asig[-64:])
    for i in range(factors//2):
        bbs0.append(Scalar(asig[64*i:64*(i+1)]))
        bbs1.append(Scalar(asig[64*64+64*i:64*64+64*(i+1)]))
        P1.append(Point(Ci[64*i:64*(i+1)]))
        P2.append(P1[i]-Scalar(2**i * 8)*dumber25519.Point(dumber25519.cn_fast_hash(str(dumber25519.G))))

    return P1,P2,bbee,bbs0,bbs1


def check_Borromean(P1,P2,bbee,bbs0,bbs1):
    # t1 = time.time()
    LV = ''
    for j in range(64):
        LL = bbee*P1[j] + bbs0[j]*dumber25519.G
        chash = dumber25519.hash_to_scalar(str(LL))
        LV += str(chash*P2[j] + bbs1[j]*dumber25519.G) 

    eeComp = dumber25519.hash_to_scalar(LV)
    # print('Time to check Borromean:', (time.time()-t1))
    return ((bbee - eeComp) == Scalar(0))
