"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "Dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

import csv
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time
import os
from more_itertools import sort_together


files_data, files_key = [],[]
current_dir = os.getcwd()
files_plot = os.listdir(current_dir+'/csvfiles/')
for files in files_plot:
    if files.count("out_test") == 1:
        files_data.append(files)
    else:
        files_key.append(files)
        


height, amount_block,nbr_txs, val_tx_vin, val_tx_vout = [],[],[],[],[]

for i in range(len(files_data)):
    filename = files_data[i]
    data = pd.read_csv('csvfiles/'+filename,header=None)

    # import ipdb;ipdb.set_trace()
    for x in range(len(data)):
        height.append(data[0][x])
        amount_block.append(data[1][x])
        nbr_txs.append(data[2][x])
        val_tx_vin.append(data[3][x])
        val_tx_vout.append(data[4][x])

plt.figure()
plt.title('Nbr txs vs height')
plt.plot(height,nbr_txs,'*')

plt.figure()
plt.title('Value vs height')
plt.plot(height,val_tx_vin,'*')

plt.figure()
plt.title('Reward plus fees per block vs height')
plt.xlabel('Block height')
plt.ylabel('Amount collected by miner')
plt.plot(height,amount_block,'*')
plt.show()

# import ipdb;ipdb.set_trace()

aheight, aamount_block,anbr_txs, aval_tx_vin, aval_tx_vout = [],[],[],[],[]
# for i in range(len(height)):

result = sort_together([height, amount_block])[1]
aamount_block = list(result)

result = sort_together([height, height])[1]
aheight = list(result)

result = sort_together([height, nbr_txs])[1]
anbr_txs = list(result)

result = sort_together([height, val_tx_vin])[1]
aval_tx_vin = list(result)

result = sort_together([height, val_tx_vout])[1]
aval_tx_vout = list(result)


hh, ab,nt, vt,sum_tx,sum_bc,sum_tx1000,sum_bc1000,vd = 0,0,0,0,0,0,0,0,0
vhh, vab,vnt, vvt,vmv,vmv1000,vvd = [],[],[],[],[],[],[]
for i in range(len(aheight)):
    hh += int(aheight[i])
    ab += int(aamount_block[i])
    nt += int(anbr_txs[i])
    vt += int(aval_tx_vin[i])
    vd += int(aval_tx_vin[i])-int(aval_tx_vout[i])
    sum_tx += int(aval_tx_vin[i])
    sum_bc += int(aamount_block[i])
    sum_tx1000 += int(aval_tx_vin[i])
    sum_bc1000 += int(aamount_block[i])

    if (i % 1000) == 0:
        vhh.append(hh/1000)
        vab.append(ab/1000)
        vnt.append(nt/1000)
        vvt.append(vt/1000)
        vvd.append(vd/1000)
        if sum_bc==0:
            vmv.append(0)
        else:
            vmv.append(sum_tx/sum_bc)

        if sum_bc1000==0:
            vmv1000.append(0)
        else:
            vmv1000.append(sum_tx1000/sum_bc1000)

        hh, ab,nt, vt,sum_tx1000,sum_bc1000 = 0,0,0,0,0,0


fg,fg_h = [],[]
for i in range(len(aval_tx_vin)):
    diff = (int(aval_tx_vin[i])-int(aval_tx_vout[i]))
    if diff>1e12:
        fg.append(diff/1e12)
        fg_h.append(aheight[i])
    if diff<0:
        print('INFLATION!!!!!!!!!!!')
        print('height: ')
        print(i)

# with open('csvfiles/'+filename) as csv_file:
# csv_read=csv.reader(csv_file, delimiter=',')

# plt.figure()
# plt.title('Amount_block vs height')
# plt.plot(vhh,vab,'*')

# plt.figure()
# plt.title('Average number of txs vs height')
# plt.plot(vhh,vnt,'*')

# plt.figure()
# plt.title('Average value transacted vs height')
# plt.plot(vhh,vvt,'*')

# plt.figure()
# plt.title('Money velocity vs height')
# plt.plot(vhh,vmv,'*')

# plt.figure()
# plt.title('Money velocity 1000 vs height')
# plt.plot(vhh,vmv1000,'*')

# plt.figure()
# plt.title('Fees greater than 1')
# plt.plot(fg_h,fg,'*')
# plt.show()

np.save('vhh',vhh)
np.save('vab',vab)
np.save('vnt',vnt)
np.save('vvt',vvt)
np.save('vmv',vmv)
np.save('vmv1000',vmv1000)
np.save('fg',fg)
np.save('fgh',fg_h)



import ipdb;ipdb.set_trace()

