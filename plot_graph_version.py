import csv
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time
import os
from more_itertools import sort_together

vhh = np.load('plot_overview/vhh.npy')
vv1 = np.load('plot_overview/vv1.npy')
vv2 = np.load('plot_overview/vv2.npy')
vtx1 = np.load('plot_overview/vtx1.npy')
vtx2 = np.load('plot_overview/vtx2.npy')
vtx3 = np.load('plot_overview/vtx3.npy')
vtx4 = np.load('plot_overview/vtx4.npy')
vtx5 = np.load('plot_overview/vtx5.npy')


number = 7
cmap = plt.get_cmap('rainbow')
colors = [cmap(i) for i in np.linspace(0, 1, number)]


plt.figure()
plt.title('Version and type vs height')
plt.xlabel('Block height')
plt.ylabel('Average transactions per block (sampled every 1000 blocks)')
plt.plot(vhh,vv1,color = colors[0], marker='o', linestyle = '', label='Version 1')
plt.plot(vhh,vv2,color = colors[1], marker= '*', linestyle = '', label='Version 2')
plt.plot(vhh,vtx1,color = colors[2], label='Type 1: MLSAG + RCTTypeFull')
plt.plot(vhh,vtx2,color = colors[3], label='Type 2: MLSAG + RCTTypeSimple')
plt.plot(vhh,vtx3,color = colors[4], label='Type 3: MLSAG + RCTTypeBulletproof')
plt.plot(vhh,vtx4,color = colors[5], label='Type 4: MLSAG + RCTTypeBulletproof2')
plt.plot(vhh,vtx5,color = colors[6], label='Type 5: CLSAG + RCTTypeBulletproof2')
plt.legend(loc='best')
plt.show()

import ipdb;ipdb.set_trace()

