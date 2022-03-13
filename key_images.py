"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
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

keys = []

for i in range(len(files_key)):
    filename = files_key[i]
    data = pd.read_csv('csvfiles/'+filename,header=None)

    for x in range(len(data)):
        keys.append(data[0][x])


print(len(keys))

if len(keys) > len(set(keys)):
    print('More than 1 key image in the output set! Something is wrong here!')
else:
    print('All the key images are different. Everything running as expected.')

# import ipdb;ipdb.set_trace()
