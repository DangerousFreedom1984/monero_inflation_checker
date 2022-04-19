"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
from os.path import exists
import verify_tx
import scan_bc

print('1. Verify a specific transaction')
print('2. Scan blockchain')
print('3. Quit')

val = input("Enter your value: ")

if val == '1':
    tx_to_check = input('Enter transaction id:')
    try:
        res = verify_tx.verify_tx(0,[str(tx_to_check)],i_tx=0,details=1)
    except KeyError:
        print('Not found. Please enter a valid transaction.')
    except Exception:
        print('Not implemented yet. Please come back later')


elif val == '2':
    print('Continue scanning...')
    # import ipdb;ipdb.set_trace()
    if exists('height.txt'):
        h = int(scan_bc.read_height())
    else:
        h = 0
        scan_bc.write_height(str(h))
    scan_bc.start_scanning(h)

elif val == '3':
    print('Bye')

else:
    print('Option unavailable')

