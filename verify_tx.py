"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import check_v1
import check_mlsag
import check_rangeproofs

import json
#from varint import encode as to_varint
import csv
import time
import multiprocessing



### TX

def verify_tx(h,tx_to_check,i_tx=0,details=0):

    # import ipdb;ipdb.set_trace()
    if len(tx_to_check)>=1:
        txs = tx_to_check
        resp_json,resp_hex = com_db.get_tx(tx_to_check,i_tx) 
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json['vout'])
    rows = len(resp_json["vin"][0]['key']['key_offsets'])

    if resp_json["version"] == 1:
        check_v1.ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,rows,details)
    else:
        # Check type
        check_mlsag.ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,rows,details)



