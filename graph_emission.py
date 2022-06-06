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
from tkinter import Tcl


files_data, files_key = [],[]
current_dir = os.getcwd()
files_plot = os.listdir(current_dir+'/emission2/')
for files in files_plot:
    if files.count("emission") == 1:
        files_data.append(files)
    else:
        files_key.append(files)
        
height, amount_block, fee_block, acc, theo_reward, theo_total = [],[],[],[],[],[]
sum_now = 0
supply = (2**64-1)*10**-12
b_reward = (supply-0)*2**-20
current = 0
sum_now = 0

import ipdb;ipdb.set_trace()
new_files = Tcl().call('lsort', '-dict', files_data)


for i in range(len(new_files)):
    filename = new_files[i]
    data = pd.read_csv('emission2/'+filename,header=None)

    for x in range(len(data)):
        sum_now += (data[1][x] - data[2][x])/1e12
        height.append(data[0][x])
        amount_block.append(data[1][x]/1e12)
        fee_block.append(data[2][x]/1e12)
        acc.append(sum_now)
        b_reward = (supply-current)*2**-20
        current = current + b_reward
        theo_reward.append(b_reward)
        theo_total.append(current)




aheight, aamount_block, afee, aacc = [],[],[],[]
# # for i in range(len(height)):

result = sort_together([height, amount_block])[1]
aamount_block = list(result)

result = sort_together([height, height])[1]
aheight = list(result)

result = sort_together([height, fee_block])[1]
afee= list(result)

result = sort_together([height, acc])[1]
aacc= list(result)



plt.figure(figsize=(16,9))
plt.title('Mining reward plus fees per block versus height')
plt.ylabel('Mining reward plus fees')
plt.xlabel('Height')
plt.plot(aheight,aamount_block,'*b')
plt.savefig('/home/ubt/Documents/inflation-xmr/codes/website_mic/mic/static/figures/emission_total16.png',
        bbox_inches = 'tight',
        transparent = True)

plt.figure(figsize=(16,9))
plt.title('Fees versus height')
plt.ylabel('Fees')
plt.xlabel('Height')
plt.plot(aheight,afee,'*b')
plt.savefig('/home/ubt/Documents/inflation-xmr/codes/website_mic/mic/static/figures/fees_total16.png',
        bbox_inches = 'tight',
        transparent = True)


# plt.figure(figsize=(16,9))
# plt.title('Fees versus height')
# plt.ylabel('Fees')
# plt.xlabel('Height')
# plt.plot(aheight,theo_reward,'*r')
# plt.plot(aheight,aamount_block,'*b')


# plt.figure(figsize=(16,9))
# plt.title('Total available versus height')
# plt.ylabel('Accumulated')
# plt.xlabel('Height')
# plt.plot(aheight,theo_total,'*r')
# plt.plot(aheight,aacc,'*b')


plt.show()

import ipdb;ipdb.set_trace()

# import ipdb;ipdb.set_trace()

