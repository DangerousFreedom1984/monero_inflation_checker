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

import csv
import time
import verify_tx


def read_height(filename):
    with open(filename, "r") as file:
        # Reading from a file
        height = int(file.read())
    return height

def write_height(filename,height):
    with open(filename, "w") as file:
        # Writing data to a file
        file.write(height)

def start_scanning(filename, h):

    filename_save_stats = 'block_stats.csv'

    while True:
        initial_time = time.time()
        params_block = {"height": h}
        block_json = com_db.get_block(params_block)
        txs = block_json["tx_hashes"]
        nbr_txs = len(txs)

        for i_tx in range(nbr_txs):
            verify_tx.verify_tx(h, txs, i_tx, 0)

        # if everything went fine so far, write scanned height to file
        time_verify = time.time() - initial_time
        print("Block: " + str(h) + " Txs: " + str(nbr_txs) + " Duration:" + str(time_verify))
        write_height(filename, str(h))
        h += 1

        with open(filename_save_stats, 'a') as csvfile:
            csvwriter = csv.writer(csvfile)
            gt = time.gmtime()
            # Block_height | Quantity of txs | Duration to verify | Date of verification
            row = [str(h),  str(nbr_txs), str(time_verify),str(gt.tm_year)+'-'+str(gt.tm_mon)+'-'+str(gt.tm_mday)+'--'+str(gt.tm_hour)+':'+str(gt.tm_min)+':'+str(gt.tm_sec)]
            csvwriter.writerow(row)
