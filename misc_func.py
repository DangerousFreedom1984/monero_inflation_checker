"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import dumber25519
from dumber25519 import Scalar, Point, PointVector
import com_db
import numpy as np

from typing import Dict, List, Tuple


def scalar_matrix(cols, rows, ind):
    if ind != 0:
        return [
            [[Scalar(0) for _ in range(ind)] for _ in range(rows)] for _ in range(cols)
        ]
    else:
        if rows != 0:
            return [[Scalar(0) for _ in range(rows)] for _ in range(cols)]
        else:
            return [Scalar(0) for _ in range(cols)]


def point_matrix(cols, rows, ind):
    if ind != 0:
        return [
            [[Scalar(0) for _ in range(ind)] for _ in range(rows)] for _ in range(cols)
        ]
    else:
        if rows != 0:
            return [[Scalar(0) for _ in range(rows)] for _ in range(cols)]
        else:
            return [Scalar(0) for _ in range(cols)]


def point_matrix_mg(pubs, masks, pseudoOuts):
    cols = len(pubs)
    mg = []
    for i in range(cols):
        mg.append(PointVector([pubs[i], masks[i] - pseudoOuts]))
    return mg


def ss_to_scalar(sss, rows, cols):
    ss_scalar = scalar_matrix(rows, cols, 0)
    for d1 in range(rows):
        for d2 in range(cols):
            ss_scalar[d1][d2] = Scalar(sss[d1][d2])
    return ss_scalar


def s_to_scalar(ss, rows):
    s_scalar = scalar_matrix(rows, 0, 0)
    for d1 in range(rows):
        s_scalar[d1] = Scalar(ss[d1])
    return s_scalar


def get_members_and_masks_in_rings(resp_json: Dict) -> Tuple[List[List[dumber25519.Point]], List[List[dumber25519.Point]]]:
    members_all, masks_all = com_db.get_members_and_masks([
        (int(vin["key"]["amount"]), int(index))
        for vin in resp_json["vin"]
        for index in np.cumsum(vin["key"]["key_offsets"])
    ])

    members = []
    masks = []
    index = 0
    for vin in resp_json["vin"]:
        length = len(vin["key"]["key_offsets"])
        members.append(members_all[index:index + length])
        masks.append(masks_all[index:index + length])
        index += length

    return members, masks

def get_pseudo_outs(resp_json, pseudo_index=0):
    if "pseudoOuts" in resp_json["rct_signatures"]:
        pseudos = Point(resp_json["rct_signatures"]["pseudoOuts"][pseudo_index])
        return pseudos
    else:
        Ptemp = Scalar(0) * dumber25519.G
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            Ptemp += Point(resp_json["rct_signatures"]["outPk"][i])
        return Ptemp + Scalar(resp_json["rct_signatures"]["txnFee"]) * dumber25519.H


def get_pseudo_outs_bp1(resp_json, pseudo_index=0):
    if "pseudoOuts" in resp_json["rctsig_prunable"]:
        pseudos = Point(resp_json["rctsig_prunable"]["pseudoOuts"][pseudo_index])
        return pseudos


def verify_ki(ki):
    str_out = "\n"
    str_out += "--------------------------------------------------------\n"
    str_out += "-------------------Checking Key Image-------------------\n"
    str_out += "--------------------------------------------------------\n"
    res = dumber25519.mul_verify_group(ki, Scalar(1))
    # import ipdb;ipdb.set_trace()
    if res != "failed":
        str_out += (
            "Point " + str(ki) + " belongs to the G subgroup.\n Everything is fine."
        )
    else:
        str_out += (
            "Point "
            + str(ki)
            + " does not belong to the G subgroup.\n Inflation may be happening!"
        )
    str_out += "\n--------------------------------------------------------\n"

    return str_out
