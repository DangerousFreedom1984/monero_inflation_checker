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

def verify_tx(tx_to_check,i_tx=0,details=0):

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
        # print('Verify v1 ...')
        check_v1.ring_sig_correct(txs,i_tx,details)
    else:
        # print('Verify v2 ...')

        message = check_mlsag.get_tx_hash_mlsag(resp_json,resp_hex)
        pubs = misc_func.get_members_in_ring(txs,i_tx,inputs,rows)
        masks = misc_func.get_masks_in_ring(resp_json,inputs,rows)

### Signature index
        # time_ver = time.time()
        for sig_ind in range(inputs):
            # import ipdb;ipdb.set_trace()
            try:
                y = multiprocessing.Process(target=check_mlsag.check_sig_mlsag, args=(resp_json,sig_ind,inputs,rows,pubs,masks,message,details ))
                y.start()
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx]) + ' ring signature failed')

        for sig_ind in range(outputs):
            # import ipdb;ipdb.set_trace()
            try:
                x = multiprocessing.Process(target=check_rangeproofs.check_sig_Borromean, args=(resp_json,sig_ind, ))
                x.start()
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' Borromean failed')
        # print('Total time verification', time.time() - time_ver)
        # print('Total time verification tx', time.time() - time_tx)


