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
import settings_df25519
import sys

def menu1():
    print("---------------------------------------")
    print("WELCOME TO THE MONERO INFLATION CHECKER")
    print("---------------------------------------")

    print(
        "Before we start, would you like to use your own full node (faster and more reliable) or use a public node (slower and less reliable)?"
    )
    print("1. My own full node")
    print("2. Public node (from Cake Wallet) - you can change at 'settings.py'")
    val = input("Enter your choice: ")

    if val == "1":
        settings_df25519.node_choice(1)
    else:
        settings_df25519.node_choice(0)

    print(" ")
    print("Ok. Done. What do you want to do now?")
    print(" ")


def menu2():
    print("1. Verify a specific transaction")
    print("2. Verify a specific block")
    print("3. Scan blockchain")
    print("4. Quit")

    val = input("Enter your choice: ")

    if val == "1":
        tx_to_check = input("Enter transaction id:")
        try:
            str_ki, str_inp, str_out, str_commit = verify_tx.verify_tx(
                0, [str(tx_to_check)], i_tx=0, details=1
            )
            print("".join(str_ki))
            print("".join(str_inp))
            print("".join(str_out))
            print("".join(str_commit))
        except KeyError:
            print("Not found. Please enter a valid transaction.")
        except Exception:
            print(
                "Please check if your node is properly running. If so, maybe there is a bug in the software. Please report the txid at monero-inflation-checker@protonmail.com. Thank you!"
            )

    elif val == "2":
        block_to_check = input("Enter block to check:")
        filename = "last_block_scanned.txt"
        scan_bc.write_height(filename, str(block_to_check))
        scan_bc.start_scanning(filename, int(block_to_check))

    elif val == "3":
        print("Continue scanning...")
        filename = "height.txt"
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h)

    elif val == "4":
        print("Bye")
        return False

    else:
        print("Option unavailable")

    return True


if __name__ == "__main__":
    n = len(sys.argv)

    if n == 1:
        menu1()
        ans = True
        while ans:
            ans = menu2()

    elif sys.argv[1] == "scan_fast":
        settings_df25519.node_choice(1)
        filename = "height.txt"
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h)

    elif sys.argv[1] == "scan_blocks":
        settings_df25519.node_choice(1)
        filename = "last_block_scanned.txt"
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h)

    else:
        print("Unknown argument.")


