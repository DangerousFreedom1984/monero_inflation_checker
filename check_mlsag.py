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

# def get_commitment_member(index,amount):

    # url = "http://localhost:18081/get_outs"
    # headers = {'Content-Type': 'application/json'}
    # rpc_input = {
           # "outputs": [{
               # "amount": amount,
               # "index": index
                # }]
           # }
    # rpc_input.update({"jsonrpc": "2.0", "id": "0"})

# # execute the rpc request
    # response = requests.post(
        # url,
        # data=json.dumps(rpc_input),
        # headers=headers)

    # return response.json()["outs"][0]["mask"]

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

    # import ipdb;ipdb.set_trace()
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
    if "pseudoOuts" in resp_json["rct_signatures"]:
        for i in range(len(resp_json["rct_signatures"]["pseudoOuts"])):
            pseudos.append(Point(resp_json["rct_signatures"]["pseudoOuts"][i]))
        return pseudos
    else:
        # import ipdb;ipdb.set_trace()
        print('No pseudoOuts')
        Ptemp = Scalar(0)*dumber25519.G
        print(str(Ptemp))
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            Ptemp += Point(resp_json["rct_signatures"]["outPk"][i])   
        return Ptemp + Scalar(resp_json["rct_signatures"]["txnFee"])*dumber25519.H


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

def generate_MLSAG(m,PK,sk,index):
    rows = len(PK)
    cols = len(PK[0])
    # I should check some stuff here like dimensions
    msg0 = ''
    msg0 += str(m)

    alpha0 = dumber25519.random_scalar()
    aG0 = alpha0 * dumber25519.G
    aHP = alpha0 * dumber25519.hash_to_point(str(PK[index][0]))
    msg0 += str(PK[index][0])
    msg0 += str(aG0)
    msg0 += str(aHP)

    alpha1 = dumber25519.random_scalar()
    aG1 = alpha1 * dumber25519.G
    msg0 += str(PK[index][1])
    msg0 += str(aG1)

    I0 = sk[0]*dumber25519.hash_to_point(str(PK[index][0]))

    import ipdb;ipdb.set_trace()
    c_old = dumber25519.hash_to_scalar(msg0)
    i = (index + 1) % rows
    if i==0:
        cc = copy.copy(c_old)
    
    ss = scalar_matrix(rows,cols,0) 

    while (i!=index):
        # print('i: ',i)
        msg = ''
        msg += str(m)

        ss[i][0] = dumber25519.random_scalar() 
        ss[i][1] = dumber25519.random_scalar() 

        L1 = ss[i][0]*dumber25519.G + c_old*PK[i][0]
        R = ss[i][0]*dumber25519.hash_to_point(str(PK[i][0]))+c_old*I0
        msg += str(PK[i][0])
        msg += str(L1)
        msg += str(R)

        L2 = ss[i][1]*dumber25519.G + c_old*PK[i][1]
        msg += str(PK[i][1])
        msg += str(L2)

        c_old = dumber25519.hash_to_scalar(msg)
        # print(c_old)
        i = (i+1)%rows
        if i==0:
            cc = copy.copy(c_old)

    import ipdb;ipdb.set_trace()
    ss[index][0] = alpha0 - c_old*sk[0]
    ss[index][1] = alpha1 - c_old*sk[1] 

    return ss, cc, I0


def check_MLSAG(m,PK, I, c, ss):
    rows = len(PK)
    cols = len(PK[0])
    c_old = copy.copy(c)
    # I should check some stuff here like dimensions
    i = 0
    msg = ''
    msg += str(m)
    # import ipdb;ipdb.set_trace()
    while i < rows:
        toHash = ''
        toHash += str(m)

        for j in range(1):
            print('Part 1 --')
            print("j: ",j)
            print("ss[j][i][0]: ",ss[i][j])
            print("pk: ",j)
            print("pk[j][i]: ",PK[i][j])
            # import ipdb;ipdb.set_trace()

            L1 = ss[i][j]*dumber25519.G + c_old*PK[i][j]
            R = ss[i][j]*dumber25519.hash_to_point(str(PK[i][j]))+c_old*I
            toHash += str(PK[i][j])
            toHash += str(L1)
            toHash += str(R)

        for j in range(1,2):
            print('Part 2 --')
            print("pk: ",j)
            print("pk[j][i]: ",PK[i][j])
            print("j: ",j)
            print("ss[j][i][1]: ",ss[i][j])
            L2 = ss[i][j]*dumber25519.G + c_old*PK[i][j]
            # R = ss[j][i][1]*dumber25519.hash_to_point(str(pk[j][i]))+c_old*I[j]
            toHash += str(PK[i][j])
            toHash += str(L2)
            # toHash += str(R)

        c_old = dumber25519.hash_to_scalar(toHash)
        i = i + 1

    import ipdb;ipdb.set_trace()
    res = c_old - c
    print(res)
    return (res == Scalar(0))



h=1400008
# tx = '74549c62bb4c7bc2e3f01b457a8528b33881b37c01fe04f76d32b778379d1945'


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

index = 1
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

print('cols', cols)
print('rows', rows)


print('PUBS :')
print(pubs)

II = []
for i in range(len(resp_json['vin'])):
    II.append(Point(resp_json["vin"][i]["key"]["k_image"]))



masks = get_masks_in_ring(resp_json,cols,rows)
import ipdb;ipdb.set_trace()
pseudoOuts = get_pseudo_outs(resp_json)
# masks = get_masks()

i = 0

sss = resp_json["rctsig_prunable"]["MGs"][i]["ss"]
ss_scalar = ss_to_scalar(sss,rows,2)



cc = Scalar(resp_json["rctsig_prunable"]["MGs"][i]["cc"])
# PK = point_matrix_mg(pubs[i],masks[i],pseudoOuts[i])
PK = point_matrix_mg(pubs[i],masks[i],pseudoOuts)
IIv = II[i]

check_MLSAG(message,PK, IIv, cc, ss_scalar)

import ipdb;ipdb.set_trace()


# message = '06bc62dbfc5a9b2d408a6a68a8d3d949fd0732f8a08067faef29e58b41c73c78'
# PK = [[Point('a9a0a41d7241649cf4f77f953287680f90a30c8878d49362b91cafd398be817c'),Point('ff4db1aee8d53b5d477ea200f20b4e4cb3615c3d8daf1cd45fe6e0d97bdd3316'),],[Point('0ada433a024c1cb115c70064b9e8e9379389c87759ab960754774689a0415721'),Point('3b7193bcb749c4bd0a5470309af38d88fee121a705a59232a6ff2f55ae5a1533'),],[Point('9855e371c4baa11f96f8afdbcf001e344a4f8ed20723a92b8bc13498d03f0750'),Point('aa12b65f356cd53f27ffcb0928846dcf43d095a346dda9e456289eac16f46e2e'),],[Point('59d87e0e3460085ce87e49322f3150dd1f8c085ee9a5b045d97179383dfe3937'),Point('3e3155e3bd7cb14a8c3dd820785ad1f32c810e078727a466bc236ffc5f7c2176'),],[Point('a91516d1fdb30eb9b37a61dba36e77caead71e276697b941d1fd84d0f25f7f6c'),Point('dfeb624430f3e81a4b7112043b8535a9b9c9193b0942f4103355500cb4f30880'),]]
# sk = [Scalar('ce3c86ee5e0174ff4314975ab48be6298801a7bfdb230de767d1847f6663fa05'),Scalar('1d4db898a3ece8d3a4982ca58b6c4deac8a54a72193570906f97d93db4d90108'),]
# index = 3


# ss, cc, I = generate_MLSAG(message,PK,sk,index)

# check_MLSAG(message,PK, I, cc, ss)
