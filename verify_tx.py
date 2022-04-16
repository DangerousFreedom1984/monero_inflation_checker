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


# scan->block,tx,sig
initial_time = time.time()

### Block
for h_plus in range(30):
    h=1232500+h_plus

    params_block = {'height':h}
    block = com_db.rpc_connection.get_block(params_block)
    block_json = json.loads(block["json"])
    txs = block_json['tx_hashes']
    nbr_tx = len(txs)
    print(h)
    # print(nbr_tx)

### TX
    for i_tx in range(nbr_tx):
        # time_tx = time.time()
        resp_json,resp_hex = com_db.get_tx(txs,i_tx) 
        inputs = len(resp_json["vin"])
        outputs = len(resp_json['vout'])
        rows = len(resp_json["vin"][0]['key']['key_offsets'])

        if resp_json["version"] == 1:
            # print('Verify v1 ...')
            check_v1.ring_sig_correct(txs,i_tx)
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
                    y = multiprocessing.Process(target=check_mlsag.check_sig_mlsag, args=(resp_json,sig_ind,inputs,rows,pubs,masks,message, ))
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

print('Total time', time.time() - initial_time)

