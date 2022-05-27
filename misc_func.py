"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector
import com_db
import numpy as np

def scalar_matrix(cols,rows,ind):
    if ind != 0:
        return [[[Scalar(0) for _ in range(ind)] for _ in range(rows)] for _ in range(cols)]
    else:
        if rows != 0:
            return [[Scalar(0) for _ in range(rows)] for _ in range(cols)]
        else:
            return [Scalar(0) for _ in range(cols)]

def point_matrix(cols,rows,ind):
    if ind != 0:
        return [[[Scalar(0) for _ in range(ind)] for _ in range(rows)] for _ in range(cols)]
    else:
        if rows != 0:
            return [[Scalar(0) for _ in range(rows)] for _ in range(cols)]
        else:
            return [Scalar(0) for _ in range(cols)]



def key_matrix(cols,rows):
    rv = [Scalar(0)*dumber25519.G] * cols
    rh = [Scalar(0)*dumber25519.G] * rows 

    for i in range(0, cols):
        rv[i] = PointVector(rh)
    return rv

def point_matrix_mg(pubs,masks,pseudoOuts):
    cols = len(pubs)
    mg = []
    for i in range(cols):
        mg.append(PointVector([pubs[i],masks[i]-pseudoOuts]))
        # print('PK['+str(i)+'][0] = ' +str(pubs[i]))
        # print('PK['+str(i)+'][1] = ' +str(masks[i]-pseudoOuts))
    return mg

def ss_to_scalar(sss,rows,cols):
    ss_scalar = scalar_matrix(rows,cols,0) 
    for d1 in range(rows):
        for d2 in range(cols):
            ss_scalar[d1][d2] = Scalar(sss[d1][d2])
    return ss_scalar

def s_to_scalar(ss,rows):
    s_scalar = scalar_matrix(rows,0,0)
    for d1 in range(rows):
        s_scalar[d1] = Scalar(ss[d1])
    return s_scalar

def get_members_in_ring(txs,index,cols,rows):
    resp_json,resp_hex = com_db.get_tx(txs,index)
    ring_members = key_matrix(cols,rows) 
    for ki in range(len(resp_json['vin'])):
        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  
        pubs_count = len(resp_json["vin"][ki]["key"]["key_offsets"])
        candidates = []
        for rm in range(pubs_count):
            candidates.append(dumber25519.Point(com_db.get_ring_members(int(indices[rm]),int(amount))))
        ring_members[ki] = dumber25519.PointVector(candidates)  
    return ring_members


def get_masks_in_ring(resp_json,cols,rows):
    mask_members = key_matrix(cols,rows) 
    for ki in range(len(resp_json['vin'])):
        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  
        pubs_count = len(resp_json["vin"][ki]["key"]["key_offsets"])
        candidates = []
        for rm in range(pubs_count):
            # import ipdb;ipdb.set_trace()
            # print(int(indices[rm]))
            # print(int(amount))
            candidates.append(dumber25519.Point(com_db.get_mask_members(int(indices[rm]),int(amount))))
        mask_members[ki] = dumber25519.PointVector(candidates)  
    return mask_members 


def get_pseudo_outs(resp_json,pseudo_index=0):
    if "pseudoOuts" in resp_json["rct_signatures"]:
        pseudos = Point(resp_json["rct_signatures"]["pseudoOuts"][pseudo_index])
        return pseudos
    else:
        Ptemp = Scalar(0)*dumber25519.G
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            Ptemp += Point(resp_json["rct_signatures"]["outPk"][i])   
        return Ptemp + Scalar(resp_json["rct_signatures"]["txnFee"])*dumber25519.H


def verify_ki(ki):

    str_out = '\n'
    str_out += '--------------------------------------------------------\n'
    str_out += '-------------------Checking Key Image-------------------\n'
    str_out += '--------------------------------------------------------\n'
    res = dumber25519.mul_verify_group(ki,Scalar(1))
    # import ipdb;ipdb.set_trace()
    if res != 'failed':
        str_out += 'Point ' +str(ki)+' belongs to the G subgroup.\n Everything is fine.'
    else:
        str_out += 'Point ' +str(ki)+' does not belong to the G subgroup.\n Inflation may be happening!'
    str_out += '\n--------------------------------------------------------\n'

    return str_out


