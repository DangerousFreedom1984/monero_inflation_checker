"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import numpy as np
import matplotlib.pyplot as plt

vhh = np.load('vhh.npy')
vmv = np.load('vmv.npy')
vnt = np.load('vnt.npy')
vvt = np.load('vvt.npy')
vab = np.load('vab.npy')

plt.figure()
plt.title('Amount_block vs height')
plt.plot(vhh,vab,'*')

plt.figure()
plt.title('Average number of txs vs height')
plt.plot(vhh,vnt,'*')

plt.figure()
plt.title('Average value transacted vs height')
plt.plot(vhh,vvt/1e12,'r*')

plt.figure()
plt.title('Money velocity vs height')
plt.plot(vhh,vmv,'*')

plt.show()
