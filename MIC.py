#!/usr/bin/env python3
"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

from os.path import exists
import verify_tx
import scan_bc
import settings
import sys


def menu1():

    print('---------------------------------------')
    print('WELCOME TO THE MONERO INFLATION CHECKER')
    print('---------------------------------------')

    print('Before we start, would you like to use your own full node (faster and more reliable) or use a public node (slower and less reliable)?')
    print('1. My own full node')
    print('2. Public node (Seth for Privacy)')
    val = input("Enter your choice: ")

    if val == '1':
        settings.node_choice(1)
    else:
        settings.node_choice(0)

    print(' ')
    print('Ok. Done. What do you want to do now?')
    print(' ')


def menu2():

    print('1. Verify a specific transaction')
    print('2. Scan blockchain')
    print('3. Quit')


    val = input("Enter your choice: ")

    if val == '1':
        tx_to_check = input('Enter transaction id:')
        try:
            str_ki,str_inp, str_out,str_commit= verify_tx.verify_tx(0,[str(tx_to_check)],i_tx=0,details=1)
            print(''.join(str_ki))
            print(''.join(str_inp))
            print(''.join(str_out))
            print(''.join(str_commit))
        except KeyError:
            print('Not found. Please enter a valid transaction.')
        except Exception:
            print('Please check if your node is properly running. If so, maybe there is a bug in the software. Please report the txid at monero-inflation-checker@protonmail.com. Thank you!')


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
        return False

    else:
        print('Option unavailable')

    return True


if __name__ == "__main__":

    n = len(sys.argv)
     
    if n == 1:
        menu1()
        ans = True
        while ans:
            ans = menu2()

    else:
        if sys.argv[1]=='scan_fast':
            settings.node_choice(1)
            print('Continue scanning...')
            # import ipdb;ipdb.set_trace()
            if exists('height.txt'):
                h = int(scan_bc.read_height())
            else:
                h = 0
                scan_bc.write_height(str(h))
            scan_bc.start_scanning(h)
        else:
            print('Unknow argument')



