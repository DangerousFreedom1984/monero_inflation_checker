"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

import json
import requests
import com_db
import misc_func
#from varint import encode as to_varint
import csv
import dumber25519
import numpy as np
import matplotlib.pyplot as plt
import time
import os
from concurrent.futures import as_completed, ProcessPoolExecutor



h=2300000
init_path = os.getcwd()
if not os.path.exists(init_path+'/emission'):
    os.mkdir(init_path+'/emission')

while h<2509827: #1009827:

    save_now = 0
    amount_block,height = [],[]
    amount_block_fees=[]
    type_block = []

    j = 0 
    initial_time = time.time()
    old_target = h
    new_target = h+10
    print('New target: '+str(new_target))
    while h<new_target:

        amount = []
        txfee = []
        txtype = []
        params_block = {'height':h}
        block_json = com_db.get_block(params_block)
        txs = block_json['tx_hashes']
        
        for i in range(len(block_json['miner_tx']['vout'])):
            amount.append(block_json['miner_tx']['vout'][i]['amount'])
            
        # Check if there are txs
        amount_all_txs_vin = 0
        amount_all_txs_vout = 0
        if len(txs)>0:

            # y = []
            # for index in range(len(txs)):
                # # import ipdb;ipdb.set_trace()
                # try:
                    # with ProcessPoolExecutor() as exe:
                        # # args = (resp_json,sig_ind,inputs,rows,pubs,masks,message,details)
                        # y.append(exe.submit(get_fee_from_tx,txs,index))
                    # # y.append(multiprocessing.Process(target=check_sig_mlsag, args=args))
                    # # y[sig_ind].start()
                    # # check_sig_mlsag(resp_json,sig_ind,inputs,rows,pubs,masks,message,details)
                    
                # except:
                    # print('Error at height: ',h)

            # for res in as_completed(y):
                # txfee.append(res.result())



            for index in range(len(txs)):
                amount_of_tx_vin = 0
                amount_of_tx_vout = 0
                # resp_json,resp_hex = get_tx(txs,index)
                resp_json,resp_hex = com_db.get_tx(txs,index) 
                # import ipdb;ipdb.set_trace()
                # import ipdb;ipdb.set_trace()
                txtype.append(resp_json["rct_signatures"]["type"])

                #if v1 
                if resp_json['version'] == 1:
                    for vv in range(len(resp_json['vin'])):
                        amount_of_tx_vin += resp_json["vin"][vv]["key"]["amount"]

                    for vo in range(len(resp_json['vout'])):
                        amount_of_tx_vout += resp_json["vout"][vo]["amount"]

                    txfee.append(amount_of_tx_vin-amount_of_tx_vout)

                # if v2:
                else:
                    txfee.append(resp_json["rct_signatures"]["txnFee"])
        else:
            txfee.append(0)

            #if version 2

        # Amount created
        type_block.append(txtype)
        amount_block.append(sum(amount))
        amount_block_fees.append(sum(txfee))
        height.append(h)


        h = h+1
    print('Time to scan: ', time.time()-initial_time)


    
    filename = init_path+'/emission/emission_'+str(old_target)+'_to_'+str(new_target)+'.csv'
    with open(filename, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        for i in range(0,new_target-old_target):
                # writing the data rows
            row = [str(height[i]), str(amount_block[i]), str(amount_block_fees[i]),str(type_block[i])]
            csvwriter.writerow(row)

import ipdb;ipdb.set_trace()

# import ipdb;ipdb.set_trace()



