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
files_plot = os.listdir(current_dir+'/csv_test1/')
for files in files_plot:
    if files.count("out_version") == 1:
        files_data.append(files)
    else:
        files_key.append(files)
        


height, amount_block,nbr_txs, val_tx_vin, val_tx_vout = [],[],[],[],[]
version_hf, version_tx_1, version_tx_2, type_tx_1, type_tx_2, type_tx_3, type_tx_4, type_tx_5, type_tx_6, type_tx_7= [],[],[],[],[],[],[],[],[],[]


for i in range(len(files_data)):
    filename = files_data[i]
    data = pd.read_csv('csvfiles/'+filename,header=None)

    for x in range(len(data)):
        height.append(data[0][x])
        amount_block.append(data[1][x])
        nbr_txs.append(data[2][x])
        version_hf.append(data[3][x])
        version_tx_1.append(data[4][x])
        version_tx_2.append(data[5][x])
        type_tx_1.append(data[6][x])
        type_tx_2.append(data[7][x])
        type_tx_3.append(data[8][x])
        type_tx_4.append(data[9][x])
        type_tx_5.append(data[10][x])
        type_tx_6.append(data[11][x])

# import ipdb;ipdb.set_trace()

# plt.figure()
# plt.title('Nbr txs vs height')
# plt.plot(height,nbr_txs,'*')

# plt.figure()
# plt.title('Value vs height')
# plt.plot(height,val_tx_vin,'*')

# plt.figure()
# plt.title('Reward plus fees per block vs height')
# plt.xlabel('Block height')
# plt.ylabel('Amount collected by miner')
# plt.plot(height,amount_block,'*')
# plt.show()

# # import ipdb;ipdb.set_trace()

v_1,v_2 = [],[] 
t_1,t_2,t_3,t_4,t_5,t_6,t_7 = [],[],[],[],[],[],[]

aheight, aamount_block,anbr_txs, av1, av2, atx1, atx2, atx3, atx4, atx5, atx6, atx7 = [],[],[],[],[],[],[],[],[],[],[],[]
# # for i in range(len(height)):

result = sort_together([height, amount_block])[1]
aamount_block = list(result)

result = sort_together([height, height])[1]
aheight = list(result)

result = sort_together([height, nbr_txs])[1]
anbr_txs = list(result)

result = sort_together([height, version_tx_1])[1]
av1 = list(result)

result = sort_together([height, version_tx_2])[1]
av2 = list(result)

result = sort_together([height, type_tx_1])[1]
atx1 = list(result)

result = sort_together([height, type_tx_2])[1]
atx2 = list(result)

result = sort_together([height, type_tx_3])[1]
atx3 = list(result)

result = sort_together([height, type_tx_4])[1]
atx4 = list(result)

result = sort_together([height, type_tx_5])[1]
atx5 = list(result)

hh, hav1,hav2,hatx1,hatx2,hatx3,hatx4,hatx5 = 0,0,0,0,0,0,0,0 
vhh, vv1, vv2, vtx1, vtx2, vtx3, vtx4, vtx5  = [],[],[],[],[],[],[],[]
for i in range(len(aheight)):
    hh += int(aheight[i])
    hav1 += int(av1[i])
    hav2 += int(av2[i])
    hatx1 += int(atx1[i])
    hatx2 += int(atx2[i])
    hatx3 += int(atx3[i])
    hatx4 += int(atx4[i])
    hatx5 += int(atx5[i])

    if (i % 1000) == 0:
        vhh.append(hh/1000)
        vv1.append(hav1/1000)
        vv2.append(hav2/1000)
        vtx1.append(hatx1/1000)
        vtx2.append(hatx2/1000)
        vtx3.append(hatx3/1000)
        vtx4.append(hatx4/1000)
        vtx5.append(hatx5/1000)
        hh, hav1,hav2,hatx1,hatx2,hatx3,hatx4,hatx5 = 0,0,0,0,0,0,0,0 


# fg,fg_h = [],[]
# for i in range(len(aval_tx_vin)):
    # diff = (int(aval_tx_vin[i])-int(aval_tx_vout[i]))
    # if diff>1e12:
        # fg.append(diff/1e12)
        # fg_h.append(aheight[i])
    # if diff<0:
        # print('INFLATION!!!!!!!!!!!')
        # print('height: ')
        # print(i)

# with open('csvfiles/'+filename) as csv_file:
# csv_read=csv.reader(csv_file, delimiter=',')
import ipdb;ipdb.set_trace()

np.save('plot_overview/vhh',vhh)
np.save('plot_overview/vv1',vv1)
np.save('plot_overview/vv2',vv2)
np.save('plot_overview/vtx1',vtx1)
np.save('plot_overview/vtx2',vtx2)
np.save('plot_overview/vtx3',vtx3)
np.save('plot_overview/vtx4',vtx4)
np.save('plot_overview/vtx5',vtx5)


number = 7
cmap = plt.get_cmap('rainbow')
colors = [cmap(i) for i in np.linspace(0, 1, number)]


plt.figure()
plt.title('Version and type vs height')
plt.plot(vhh,vv1,color = colors[0], label='Version 1')
plt.plot(vhh,vv2,color = colors[1], label='Version 2')
plt.plot(vhh,vtx1,color = colors[2], label='MLSAG + RCTTypeFull')
plt.plot(vhh,vtx2,color = colors[3], label='MLSAG + RCTTypeSimple')
plt.plot(vhh,vtx3,color = colors[4], label='MLSAG + RCTTypeBulletproof')
plt.plot(vhh,vtx4,color = colors[5], label='MLSAG + RCTTypeBulletproof2')
plt.plot(vhh,vtx5,color = colors[6], label='CLSAG + RCTTypeBulletproof3')
plt.legend(loc='best')
plt.show()

import ipdb;ipdb.set_trace()

np.save('plot_overview/vhh',vhh)
np.save('plot_overview/vv1',vv1)
np.save('plot_overview/vv2',vv2)
np.save('plot_overview/vtx1',vtx1)
np.save('plot_overview/vtx2',vtx2)
np.save('plot_overview/vtx3',vtx3)
np.save('plot_overview/vtx4',vtx4)
np.save('plot_overview/vtx5',vtx5)

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

# np.save('vhh',vhh)
# np.save('vab',vab)
# np.save('vnt',vnt)
# np.save('vvt',vvt)
# np.save('vmv',vmv)
# np.save('vmv1000',vmv1000)
# np.save('fg',fg)
# np.save('fgh',fg_h)



# import ipdb;ipdb.set_trace()

