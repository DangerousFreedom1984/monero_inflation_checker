"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

from monerorpc.authproxy import AuthServiceProxy, JSONRPCException
import json
import requests
#from varint import encode as to_varint
import csv
import check_sigs
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector
import numpy as np
import matplotlib.pyplot as plt
import time
import os
import copy


# Execute on monerod: ./monerod --rpc-bind-port 18081 --rpc-login username:password
username,password = 'username','password'
rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))


def get_ring_members(index,amount):

    url = "http://localhost:18081/get_outs"
    headers = {'Content-Type': 'application/json'}
    rpc_input = {
           "outputs": [{
               "amount": amount,
               "index": index
                }]
           }
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

# execute the rpc request
    response = requests.post(
        url,
        data=json.dumps(rpc_input),
        headers=headers)

    return response.json()["outs"][0]["key"]

def get_mask_members(index,amount):

    url = "http://localhost:18081/get_outs"
    headers = {'Content-Type': 'application/json'}
    rpc_input = {
           "outputs": [{
               "amount": amount,
               "index": index
                }]
           }
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

# execute the rpc request
    response = requests.post(
        url,
        data=json.dumps(rpc_input),
        headers=headers)

    return response.json()["outs"][0]["mask"]

def get_tx(txs,index):

    url = "http://localhost:18081/get_transactions"
    headers = {'Content-Type': 'application/json'}
    rpc_input = {
           "txs_hashes": txs, "decode_as_json": True 
           }
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

# execute the rpc request
    response = requests.post(
        url,
        data=json.dumps(rpc_input),
        headers=headers)


    resp_json = json.loads(response.json()["txs"][index]["as_json"])
    resp_hex = response.json()["txs"][index]["as_hex"]

    return resp_json,resp_hex

def key_matrix(cols,rows):
    #first index is columns (so slightly backward from math)
    rv = [Scalar(0)*dumber25519.G] * cols
    rh = [Scalar(0)*dumber25519.G] * rows 

    for i in range(0, cols):
        rv[i] = PointVector(rh)
    return rv

def scalar_matrix(cols,rows,ind):
    return [[[Scalar(0) for _ in range(ind)] for _ in range(rows)] for _ in range(cols)]
                

def get_members_in_ring(txs,index,cols,rows):
    resp_json,resp_hex = get_tx(txs,index)

    # tx_prefix = get_tx_prefix_hash(resp_json,resp_hex)
    # cols = 
    ring_members = key_matrix(cols,rows) 

    for ki in range(len(resp_json['vin'])):

        # pubs_count,sigr,sigc = get_signatures(resp_json,resp_hex,ki)
        # key_image = get_key_image(resp_json,ki)

        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  

        pubs_count = len(resp_json["vin"][ki]["key"]["key_offsets"])
        candidates = []
        for rm in range(pubs_count):
            # import ipdb;ipdb.set_trace()
            # print('Offset: ')
            # print(int(indices[rm]))
            candidates.append(dumber25519.Point(get_ring_members(int(indices[rm]),int(amount))))
            # print('Ring member: ')
            # print(candidates[rm])

        # print(candidates)
        ring_members[ki] = dumber25519.PointVector(candidates)  

    return ring_members

def get_masks_in_ring(resp_json,cols,rows):
    # tx_prefix = get_tx_prefix_hash(resp_json,resp_hex)
    # cols = 
    mask_members = key_matrix(cols,rows) 

    for ki in range(len(resp_json['vin'])):

        # pubs_count,sigr,sigc = get_signatures(resp_json,resp_hex,ki)
        # key_image = get_key_image(resp_json,ki)

        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  

        pubs_count = len(resp_json["vin"][ki]["key"]["key_offsets"])
        candidates = []
        for rm in range(pubs_count):
            # import ipdb;ipdb.set_trace()
            # print('Offset: ')
            # print(int(indices[rm]))
            candidates.append(dumber25519.Point(get_mask_members(int(indices[rm]),int(amount))))
            # print('Ring member: ')
            # print(candidates[rm])

        # print(candidates)
        mask_members[ki] = dumber25519.PointVector(candidates)  

    return mask_members 

def ring_sig_correct(txs,index):

    resp_json,resp_hex = get_tx(txs,index)

    tx_prefix = get_tx_prefix_hash(resp_json,resp_hex)

    for ki in range(len(resp_json['vin'])):

        pubs_count,sigr,sigc = get_signatures(resp_json,resp_hex,ki)
        key_image = get_key_image(resp_json,ki)

        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  

        candidates = []
        for rm in range(pubs_count):
            # import ipdb;ipdb.set_trace()
            # print('Offset: ')
            # print(int(indices[rm]))
            candidates.append(dumber25519.Point(get_ring_members(int(indices[rm]),int(amount))))
            # print('Ring member: ')
            # print(candidates[rm])

        # print(candidates)
        pubs = dumber25519.PointVector(candidates)  

        # print('verifying ring: ')
        verified,str_out = check_sigs.check_ring_signature(tx_prefix, key_image, pubs, pubs_count, sigr, sigc)
        if verified == False:
            print('Signatures dont match! Verify this block')
        # print(verified)

    return verified 

# Get Matrix of public keys
# PseudoOuts - Mask = pk2

def get_pseudo_outs(resp_json):

    pseudos =[]
    for i in range(len(resp_json["rct_signatures"]["pseudoOuts"])):
        pseudos.append(Point(resp_json["rct_signatures"]["pseudoOuts"][i]))
    return pseudos

def point_matrix_mg(pubs,masks,pseudoOuts):
    cols = len(pubs)
    mg = []
    for i in range(cols):
        mg.append(PointVector([pubs[i],masks[i]-pseudoOuts]))
    return mg

def ss_to_scalar(sss,rows,cols):

    ss_scalar = scalar_matrix(rows,cols,0) 
    for d1 in range(rows):
        for d2 in range(cols):
            ss_scalar[d1][d2] = Scalar(sss[d1][d2])
    return ss_scalar

# masks = get_masks()
# MG = point_matrix_pk(pubs)

# resp_json["rct_signatures"]["pseudoOuts"][0]
# def point_matrix_pk(pubs,pseudoOuts,masks):


def check_MLSAG(m,pk, I, c, ss):
    #Continue here... compare with original code
    import ipdb;ipdb.set_trace()
    rows = len(pk)
    cols = len(pk[0])
    c_old = copy.copy(c)
    # Check some stuff here
    i = 0
    msg = ''
    msg += m
    while i < rows:
        toHash = ''
        toHash += m

        for j in range(1):
            print('Part 1 --')
            print("j: ",j)
            print("ss[j][i][0]: ",ss[i][j])
            print("pk: ",j)
            print("pk[j][i]: ",pk[i][j])

            L1 = ss[i][j]*dumber25519.G + c_old*pk[i][j]
            R = ss[i][j]*dumber25519.hash_to_point(str(pk[i][j]))+c_old*I
            toHash += str(pk[i][j])
            toHash += str(L1)
            toHash += str(R)

        for j in range(1,2):
            print('Part 2 --')
            print("pk: ",j)
            print("pk[j][i]: ",pk[i][j])
            print("j: ",j)
            print("ss[j][i][1]: ",ss[i][j])
            L2 = ss[i][j]*dumber25519.G + c_old*pk[i][j]
            # R = ss[j][i][1]*dumber25519.hash_to_point(str(pk[j][i]))+c_old*I[j]
            toHash += str(pk[i][j])
            toHash += str(L2)
            # toHash += str(R)

        c_old = dumber25519.hash_to_scalar(toHash)
        i = i + 1

    import ipdb;ipdb.set_trace()
    res = c_old - c
    print(res)
    return (res == Scalar(0))



h=1400005
tx = '74549c62bb4c7bc2e3f01b457a8528b33881b37c01fe04f76d32b778379d1945'


save_now = 0
key_image_miner,key_image_ring, amount,amount_block,tx_valid,nbr_txs,height,val_tx_vin,val_tx_vout = [],[],[],[],[],[],[],[],[]

j = 0 
initial_time = time.time()
old_target = h
new_target = h+10000
print('New target: '+str(new_target))

amount = []
params_block = {'height':h}
block = rpc_connection.get_block(params_block)

block_json = json.loads(block["json"])
txs = block_json['tx_hashes']
    
# Number of txs
nbr_txs.append(len(txs))

index = 0
resp_json,resp_hex = get_tx(txs,index) 
ecdh = resp_json["rct_signatures"]["ecdhInfo"]

MGs = resp_json["rctsig_prunable"]["MGs"]
ss = resp_json["rctsig_prunable"]["MGs"][0]["ss"]
cc = resp_json["rctsig_prunable"]["MGs"][0]["cc"]
Ci = resp_json["rctsig_prunable"]["rangeSigs"][0]["Ci"]


extra_hex = ''
for i in range(len(resp_json['extra'])):
    extra_hex += format(resp_json["extra"][i],'02x')



ph1 = resp_hex.split(extra_hex)[0] + extra_hex

asig = resp_json["rctsig_prunable"]["rangeSigs"][0]["asig"]

ph2 = resp_hex.split(extra_hex)[1].split(asig)[0]

ph3 = resp_hex.split(resp_json["rct_signatures"]["outPk"][-1])[1].split(ss[0][0])[0]


ph1_hash = dumber25519.cn_fast_hash(ph1)
ph2_hash = dumber25519.cn_fast_hash(ph2)
ph3_hash = dumber25519.cn_fast_hash(ph3)

message = dumber25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)

cols = len(resp_json["vin"])
rows = len(resp_json["vin"][0]['key']['key_offsets'])
pubs = get_members_in_ring(txs,index,cols,rows)

print('PUBS :')
print(pubs)

II = []
for i in range(len(resp_json['vin'])):
    II.append(Point(resp_json["vin"][i]["key"]["k_image"]))



masks = get_masks_in_ring(resp_json,cols,rows)
pseudoOuts = get_pseudo_outs(resp_json)
# masks = get_masks()

i = 0

sss = resp_json["rctsig_prunable"]["MGs"][i]["ss"]
ss_scalar = ss_to_scalar(sss,rows,cols)



cc = Scalar(resp_json["rctsig_prunable"]["MGs"][i]["cc"])
MG = point_matrix_mg(pubs[i],masks[i],pseudoOuts[i])
IIv = II[i]

# import ipdb;ipdb.set_trace()
check_MLSAG(message,MG, IIv, cc, ss_scalar)
