# Execute on monerod: ./monerod --rpc-bind-port 18081 --rpc-login username:password

from monerorpc.authproxy import AuthServiceProxy, JSONRPCException
import json
import requests


username,password = 'username','password'
rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))


##### Get txs


# bitmonerod is running on the localhost and port of 18081
url = "http://localhost:18081/get_transactions"

# standard json header
headers = {'Content-Type': 'application/json'}

# the block to get
txs = ['beb76a82ea17400cd6d7f595f70e1667d2018ed8f5a78d1ce07484222618c3cd']

# bitmonerod' procedure/method to call
rpc_input = {
       "txs_hashes": txs, "decode_as_json": True 
       }


# add standard rpc values
rpc_input.update({"jsonrpc": "2.0", "id": "0"})

# execute the rpc request
response = requests.post(
    url,
    data=json.dumps(rpc_input),
    headers=headers)

resp_dict = json.loads(response.json()["txs"][0]["as_json"])

# pretty print json output
print(json.dumps(response.json(), indent=4))

import ipdb;ipdb.set_trace()

##### Get txs

# params = {'height':0}
# info = rpc_connection.get_info()
# print(info)

j = 0 
h = 0
key_image, amount = [],[]
while j<2:

    params_block = {'height':h}
    block = rpc_connection.get_block(params_block)

    block_json = json.loads(block["json"])
    txs = block_json['tx_hashes']
    

    print(block['block_header']['height'])

    for i in range(len(block_json['miner_tx']['vout'])):
        key_image.append(block_json['miner_tx']['vout'][i]['target']['key'])
        amount.append(block_json['miner_tx']['vout'][i]['amount'])
        
    

    if len(txs)>0:
        print('----- transaction -----')
        print(block['block_header']['height'])
        #block 110
        j = j+1 

    h = h+1
# print(h)
#print(block)
import ipdb;ipdb.set_trace()

