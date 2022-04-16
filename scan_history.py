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
import numpy as np
import matplotlib.pyplot as plt
import time
import os


# Execute on monerod: ./monerod --rpc-bind-port 18081 --rpc-login username:password
username,password = 'username','password'
rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))



def get_tx_prefix_hash(resp_json,resp_hex):
    signatures = resp_json['signatures']
    sig = signatures[0]
    tx_prefix_raw = resp_hex.split(sig)[0]
    tx_prefix_hash = dumber25519.cn_fast_hash(tx_prefix_raw)
    return tx_prefix_hash.encode()


def get_signatures(resp_json,resp_hex,index):
    signatures = resp_json['signatures']
    sig = signatures[index]

    n_ring_members = len(sig)//(64*2)
    sc,sr = [],[]

    for i in range(0,int(2*n_ring_members),2):
        sc.append(dumber25519.Scalar(sig[int(i*64):int((i+1)*64)]))
        sr.append(dumber25519.Scalar(sig[int((i+1)*64):int((i+2)*64)]))

    sigc = dumber25519.ScalarVector(sc)
    sigr = dumber25519.ScalarVector(sr)

    return n_ring_members,sigr,sigc

def get_key_image(resp_json,index):
    image = resp_json["vin"][index]["key"]["k_image"]
    return image


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


init_path = os.getcwd()
if not os.path.exists(init_path+'/csvfiles'):
    os.mkdir(init_path+'/csvfiles')

h=2240000
while h<2555555: #1009827:

    save_now = 0
    key_image_miner,key_image_ring, amount,amount_block,tx_valid,nbr_txs,height,val_tx_vin,val_tx_vout = [],[],[],[],[],[],[],[],[]
    version_hf, version_tx_1, version_tx_2, type_tx_1, type_tx_2, type_tx_3, type_tx_4, type_tx_5, type_tx_6, type_tx_7= [],[],[],[],[],[],[],[],[],[]

    j = 0 
    initial_time = time.time()
    old_target = h
    new_target = h+10000
    print('New target: '+str(new_target))
    while h<new_target:
        v_1,v_2 = [],[] 
        t_1,t_2,t_3,t_4,t_5,t_6,t_7 = [],[],[],[],[],[],[]

        amount = []
        params_block = {'height':h}
        block = rpc_connection.get_block(params_block)

        block_json = json.loads(block["json"])
        txs = block_json['tx_hashes']

        # import ipdb;ipdb.set_trace()
        
        for i in range(len(block_json['miner_tx']['vout'])):
            # key_image_miner.append(block_json['miner_tx']['vout'][i]['target']['key'])
            amount.append(block_json['miner_tx']['vout'][i]['amount'])

            
        # Number of txs
        nbr_txs.append(len(txs))
        version_hf.append(block_json["major_version"])
        if block_json["miner_tx"]["version"] == 1:
            v_1.append(1)
        else:
            v_2.append(1)


        # Check if there are txs
        if len(txs)>0:
            for index in range(len(txs)):
                resp_json,resp_hex = get_tx(txs,index)
                if resp_json["version"] == 1:
                    v_1.append(1)
                else:
                    v_2.append(1)
                    if resp_json['rct_signatures']['type'] == 1:
                        t_1.append(1)
                    elif resp_json['rct_signatures']['type'] == 2:
                        t_2.append(1)
                    elif resp_json['rct_signatures']['type'] == 3:
                        t_3.append(1)
                    elif resp_json['rct_signatures']['type'] == 4:
                        t_4.append(1)
                    elif resp_json['rct_signatures']['type'] == 5:
                        t_5.append(1)
                    elif resp_json['rct_signatures']['type'] == 6:
                        t_6.append(1)
                    elif resp_json['rct_signatures']['type'] == 0:
                        t_7.append(1)

                # import ipdb;ipdb.set_trace()

        # Amount created
        amount_block.append(sum(amount))
        version_tx_1.append(sum(v_1))
        version_tx_2.append(sum(v_2))
        type_tx_1.append(sum(t_1))
        type_tx_2.append(sum(t_2))
        type_tx_3.append(sum(t_3))
        type_tx_4.append(sum(t_4))
        type_tx_5.append(sum(t_5))
        type_tx_6.append(sum(t_6))
        type_tx_7.append(sum(t_7))

        height.append(h)
        h = h+1
    print('Time to scan: ', time.time()-initial_time)


    
    filename = init_path+'/csvfiles/out_version_'+str(old_target)+'_to_'+str(new_target)+'.csv'
    with open(filename, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        for i in range(0,new_target-old_target):
                # writing the data rows
            row = [str(height[i]), str(amount_block[i]), str(nbr_txs[i]),str(version_hf[i]),str(version_tx_1[i]),str(version_tx_2[i]),
                    str(type_tx_1[i]),str(type_tx_2[i]),str(type_tx_3[i]),str(type_tx_4[i]),str(type_tx_5[i]),str(type_tx_6[i]),str(type_tx_7[i])]        
            csvwriter.writerow(row)

    # filename = init_path+'/csvfiles/k_images_'+str(old_target)+'_to_'+str(new_target)+'.csv'
    # with open(filename, 'w') as csvfile:
        # csvwriter = csv.writer(csvfile)
        # for i in range(len(key_image_ring)):
                # # writing the data rows
            # row = [str(key_image_ring[i])]        
            # csvwriter.writerow(row)


# import ipdb;ipdb.set_trace()



