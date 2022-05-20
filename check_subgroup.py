"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import json
#from varint import encode as to_varint
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector
import copy

def check_group(h,resp_json,inputs,outputs):
        for sig_ind in range(inputs):
            Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
            res = misc_func.verify_point(Iv)
            if res == False:
                print('Point ' +str(Iv)+' does not belong to the prime subgroup.\n Inflation may be happening!')
                with open("points_subgroup.txt", "a+") as file1:
                    # Writing data to a file
                    file1.write('\n'+str(Iv)+' '+str(h)+' key_image')

        for sig_ind in range(outputs):
            Iv = Point(resp_json["vout"][sig_ind]["target"]["key"])
            res = misc_func.verify_point(Iv)
            if res == False:
                print('Point ' +str(Iv)+' does not belong to the prime subgroup.\n Inflation may be happening!')
                with open("points_subgroup.txt", "a+") as file1:
                    # Writing data to a file
                    file1.write('\n'+str(Iv)+' '+str(h)+' stealth_address')
