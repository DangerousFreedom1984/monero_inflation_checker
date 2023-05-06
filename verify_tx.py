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
import check_clsag
import check_rangeproofs

import json
import csv
import time
import multiprocessing


def verify_tx(h,tx_to_check,i_tx=0,details=0):

    if len(tx_to_check)>=1:
        txs = tx_to_check
        resp_json,resp_hex = com_db.get_tx(tx_to_check,i_tx) 
    else:
        return 0

    inputs = len(resp_json['vin'])
    outputs = len(resp_json['vout'])

    if resp_json["version"] == 1:
        if "gen" in resp_json["vin"][0]:
            amount = 0
            for i in range(outputs):
                amount += resp_json['vout'][i]['amount']
            print('Miner transaction. Total amount mined and transaction fees: ' + str(amount/1e12)+' XMR.')
        else:
            str_ki, str_inp, str_out, str_commit = check_v1.ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details)


    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2: #RCTTypeSimple and RCTTypeFull
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details)
        elif type_tx == 3 or type_tx == 4: #RCTTypeBulletproof and RCTTypeBulletproof2
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct_bp1(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details)
        elif type_tx == 5: #RCTTypeCLSAG
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp1(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details)
        elif type_tx == 6: #RCTTypeBulletproofPlus
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp_plus(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details)

        elif type_tx == 0:
            amount = 0
            for i in range(outputs):
                amount += resp_json['vout'][i]['amount']
            print('Miner transaction. Total amount mined and transaction fees: ' + str(amount/1e12)+' XMR.')
        else:
            raise Exception

    return str_ki,str_inp, str_out,str_commit

