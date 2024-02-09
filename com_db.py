"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

import json
import requests
import settings
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector

# Execute on monerod: ./monerod --rpc-bind-port 18081 --rpc-login username:password
# username,password = 'username','password'
# rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))

# curl http://127.0.0.1:18081/get_transactions -d '{"txs_hashes":["d6e48158472848e6687173a91ae6eebfa3e1d778e65252ee99d7515d63090408"]}' -H 'Content-Type: application/json'
# curl http://127.0.0.1:18081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":912345}}' -H 'Content-Type: application/json'


def get_block(params_block):
    url = settings.url_str + "json_rpc"
    headers = {"Content-Type": "application/json"}
    rpc_input = {"method": "get_block", "params": params_block, "decode_as_json": True}
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

    # execute the rpc request
    response = requests.post(url, data=json.dumps(rpc_input), headers=headers)

    resp_json = json.loads(response.json()["result"]["json"])

    return resp_json


def get_ring_members(index, amount):
    url = settings.url_str + "get_outs"
    headers = {"Content-Type": "application/json"}
    rpc_input = {"outputs": [{"amount": amount, "index": index}]}
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

    # execute the rpc request
    response = requests.post(url, data=json.dumps(rpc_input), headers=headers)

    return response.json()["outs"][0]["key"]


def get_mask_members(index, amount):
    url = settings.url_str + "get_outs"
    headers = {"Content-Type": "application/json"}
    rpc_input = {"outputs": [{"amount": amount, "index": index}]}
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

    # execute the rpc request
    response = requests.post(url, data=json.dumps(rpc_input), headers=headers)

    return response.json()["outs"][0]["mask"]

def get_members_and_masks(index, amount):
    url = settings.url_str + "get_outs"
    headers = {"Content-Type": "application/json"}
    rpc_input = {"outputs": [{"amount": amount, "index": index}]}
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

    # execute the rpc request
    response = requests.post(url, data=json.dumps(rpc_input), headers=headers)

    return [dumber25519.Point(response.json()["outs"][0]["key"]),dumber25519.Point(response.json()["outs"][0]["mask"])]

def get_tx(txs, index):
    url = settings.url_str + "get_transactions"
    headers = {"Content-Type": "application/json"}
    rpc_input = {"txs_hashes": txs, "decode_as_json": True}
    rpc_input.update({"jsonrpc": "2.0", "id": "0"})

    # execute the rpc request
    response = requests.post(url, data=json.dumps(rpc_input), headers=headers)

    resp_json = json.loads(response.json()["txs"][index]["as_json"])
    resp_hex = response.json()["txs"][index]["as_hex"]

    return resp_json, resp_hex
