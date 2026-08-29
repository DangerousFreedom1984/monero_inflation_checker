
from mic import paths
#!/usr/bin/env python3
"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""


from os.path import exists
from mic.chain import verify_tx
from mic.chain import scan_bc
from mic.common import settings_df25519
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
    print("0. Quit")
    print("1. Verify a specific transaction")
    print("2. Verify a specific block")
    print("3. Scan blockchain")
    print("4. Scan all Points and Scalars")

    val = input("Enter your choice: ")

    if val == "0":
        print("Bye")
        return False

    elif val == "1":
        tx_to_check = input("Enter transaction id:")
        if not verify_tx.verify_tx([str(tx_to_check)], i_tx=0):
            print("Failed. Transaction might not be valid.")
        else:
            print("Transaction is valid.")

    elif val == "2":
        block_to_check = input("Enter block to check:")
        filename = paths.stats_path("last_block_scanned.txt")
        scan_bc.write_height(filename, str(block_to_check))
        scan_bc.start_scanning(filename, int(block_to_check), False)

    elif val == "3":
        print("Continue scanning...")
        filename = paths.stats_path("height.txt")
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h, True)

    elif val == "4":
        print("Continue scanning...")
        filename = paths.stats_path("height_pc.txt")
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning_precheck(filename, h, True)

    elif val == "17":
        print("Benchmarking...")
        scan_bc.txs_to_benchmark()

    elif val == "18":
        print("Problematic txs...")
        scan_bc.problematic_txs()

    else:
        print("Option unavailable")

    return True


if __name__ == "__main__":
    settings_df25519.logger_basic.info("Starting program.")

    n = len(sys.argv)

    if n == 1:
        menu1()
        ans = True
        while ans:
            ans = menu2()

    elif sys.argv[1] == "scan_fast":
        settings_df25519.node_choice(1)
        filename = paths.stats_path("height.txt")
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h)

    elif sys.argv[1] == "scan_blocks":
        settings_df25519.node_choice(0)
        filename = paths.stats_path("last_block_scanned.txt")
        if exists(filename):
            h = int(scan_bc.read_height(filename))
        else:
            h = 0
            scan_bc.write_height(filename, str(h))
        scan_bc.start_scanning(filename, h)

    else:
        print("Unknown argument.")
