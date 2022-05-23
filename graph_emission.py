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
files_plot = os.listdir(current_dir+'/emission2/')
for files in files_plot:
    if files.count("emission") == 1:
        files_data.append(files)
    else:
        files_key.append(files)
        
height, amount_block, fee_block= [],[],[]

for i in range(len(files_data)):
    filename = files_data[i]
    data = pd.read_csv('emission2/'+filename,header=None)

    for x in range(len(data)):
        height.append(data[0][x])
        amount_block.append(data[1][x])
        fee_block.append(data[2][x])



aheight, aamount_block, afee = [],[],[]
# # for i in range(len(height)):

result = sort_together([height, amount_block])[1]
aamount_block = list(result)

result = sort_together([height, height])[1]
aheight = list(result)

result = sort_together([height, fee_block])[1]
afee= list(result)




plt.figure()
plt.title('Mining reward plus fees per block versus height')
plt.ylabel('Mining reward plus fees')
plt.xlabel('Height')
plt.plot(aheight,aamount_block,'*')

plt.figure()
plt.title('Fees')
plt.plot(aheight,afee,'*')
plt.show()

import ipdb;ipdb.set_trace()

# import ipdb;ipdb.set_trace()

