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



filename = 'points_subgroup.txt'
data = pd.read_csv(filename,header=None)
addr,height,t =[],[],[]

for x in range(len(data)):
    str_file = data[0][x].split()
    addr.append(str_file[0])
    height.append(str_file[1])
    t.append(str_file[2])


import ipdb;ipdb.set_trace()
pout = set(addr)
qpout = len(pout)
# # for i in range(len(height)):

