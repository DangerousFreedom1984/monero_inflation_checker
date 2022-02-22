# Execute on monerod: ./monerod --rpc-bind-port 18081 --rpc-login username:password

from monerorpc.authproxy import AuthServiceProxy, JSONRPCException
import json
import requests
from varint import encode as to_varint
import csv
import check_sigs
import dumb25519
import numpy as np


username,password = 'username','password'
rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))


# def get_ring_members(heights,amount):

    # members = len(heights)
    # candidates = []
    # import ipdb;ipdb.set_trace()


    # for rm in range(members):
        # params_block = {'height':int(heights[rm])}
        # block = rpc_connection.get_block(params_block)
        # block_json = json.loads(block["json"])

        # # Check possible members in the mined outputs
        # mined_candidates = len(block_json["miner_tx"]["vout"])
        # for i in range(mined_candidates):
            # if block_json["miner_tx"]["vout"][i]['amount'] == amount:
                # candidates.append(dumb25519.Point(block_json["miner_tx"]["vout"][i]["target"]["key"]))

    # # Maybe have to scan in the transactions also
    # print('Ring members')
    # print(candidates)

    # return dumb25519.PointVector(candidates)


def get_tx_prefix_hash(resp_json,resp_hex):
    signatures = resp_json['signatures']
    sig = signatures[0]
    tx_prefix_raw = resp_hex.split(sig)[0]
    tx_prefix_hash = dumb25519.cn_fast_hash(tx_prefix_raw)
    return tx_prefix_hash.encode()


def get_signatures(resp_json,resp_hex,index):
    signatures = resp_json['signatures']
    sig = signatures[index]

    n_ring_members = len(sig)//(64*2)
    sc,sr = [],[]

    for i in range(0,int(2*n_ring_members),2):
        sc.append(dumb25519.Scalar(sig[int(i*64):int((i+1)*64)]))
        sr.append(dumb25519.Scalar(sig[int((i+1)*64):int((i+2)*64)]))

    sigc = dumb25519.ScalarVector(sc)
    sigr = dumb25519.ScalarVector(sr)

    return n_ring_members,sigr,sigc

def get_key_image(resp_json,index):
    # len(resp_json["vin"])
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


def ring_sig_correct(txs):
# bitmonerod is running on the localhost and port of 18081
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


    resp_json = json.loads(response.json()["txs"][0]["as_json"])
    resp_hex = response.json()["txs"][0]["as_hex"]


    tx_prefix = get_tx_prefix_hash(resp_json,resp_hex)

    for ki in range(len(resp_json['vin'])):

        pubs_count,sigr,sigc = get_signatures(resp_json,resp_hex,ki)
        key_image = get_key_image(resp_json,ki)

        amount = resp_json["vin"][ki]["key"]["amount"]
        indices = np.cumsum(resp_json["vin"][ki]["key"]["key_offsets"])  

        # import ipdb;ipdb.set_trace()
        candidates = []
        for rm in range(pubs_count):
            # import ipdb;ipdb.set_trace()
            candidates.append(dumb25519.Point(get_ring_members(int(indices[rm]),int(amount))))

        print(candidates)
        pubs = dumb25519.PointVector(candidates)  

        print('verifying ring: ')
        verified = check_sigs.check_ring_signature(tx_prefix, key_image, pubs, pubs_count, sigr, sigc)
        print(verified)

    return verified 



j = 0 
h = 0
key_image, amount,amount_block,tx_valid,nbr_txs,height  = [],[],[],[],[],[]
while h<1000:


    amount = []
    params_block = {'height':h}
    block = rpc_connection.get_block(params_block)

    block_json = json.loads(block["json"])
    txs = block_json['tx_hashes']
    
    import ipdb;ipdb.set_trace()

    # Check created XMR
    print(block['block_header']['height'])

    for i in range(len(block_json['miner_tx']['vout'])):
        key_image.append(block_json['miner_tx']['vout'][i]['target']['key'])
        amount.append(block_json['miner_tx']['vout'][i]['amount'])
        
    # Check txs


        # Number of txs
    nbr_txs.append(len(txs))

    # Check if there are txs
    if len(txs)>0:
        print('----- transaction -----')
        print(block['block_header']['height'])
        #block 110

        # Valid ring signatures?
        if ring_sig_correct(txs):
            tx_valid.append(1)
        else:
            tx_valid.append(0)
        j = j+1 

    

    # Amount created
    amount_block.append(sum(amount))

    height.append(h)
    

    h = h+1
# print(h)
#print(block)


initial_height = 0
latest_height = h-2


filename = 'out1test.csv'
with open(filename, 'w') as csvfile:
    csvwriter = csv.writer(csvfile)
    for i in range(0,latest_height):
            # writing the data rows
        row = [str(height[i]), str(amount_block[i]), str(tx_valid[i]), str(nbr_txs[i])]        
        csvwriter.writerow(row)



import ipdb;ipdb.set_trace()



