"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import json
import df25519
from df25519 import (
    Scalar,
    Point,
    PointVector,
    ScalarVector,
    hash_to_point,
    hash_to_scalar,
    random_scalar,
)
import copy
import multiprocessing
import check_rangeproofs
from concurrent.futures import as_completed, ProcessPoolExecutor
import time
import settings_df25519

def ring_sig_correct_bp1(h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = get_tx_hash_clsag(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    str_ki = []
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        str_ki.append(misc_func.verify_ki(Iv))

    y = []
    for sig_ind in range(inputs):
        try:
            with ProcessPoolExecutor() as exe:
                y.append(
                    exe.submit(
                        check_sig_clsag_bp1,
                        resp_json,
                        sig_ind,
                        inputs,
                        rows,
                        pubs,
                        masks,
                        message,
                    )
                )

        except:
            print(
                "Verify block_height: "
                + str(h)
                + " tx : "
                + str(txs[i_tx])
                + " ring signature failed"
            )

    str_inp = []
    for res in as_completed(y):
        str_inp.append(res.result())

    x = []
    for sig_ind in range(1):
        try:
            with ProcessPoolExecutor() as exe:
                x.append(exe.submit(check_rangeproofs.check_sig_bp1, resp_json))
        except:
            print(
                "Verify block_height: "
                + str(h)
                + " tx : "
                + str(txs[i_tx])
                + " Bulletproofs failed"
            )

    str_out = []
    for res in as_completed(x):
        str_out.append(res.result())

    try:
        str_commits = check_rangeproofs.check_commitments_bp1(resp_json)
    except:
        print(
            "Verify block_height: "
            + str(h)
            + " tx : "
            + str(txs[i_tx])
            + " commitments check failed"
        )

    return str_ki, str_inp, str_out, str_commits
#--------------------------------------------------------------------------------------------
def ring_sig_correct_bp_plus(
    h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = get_tx_hash_clsag_bp_plus(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    str_ki, str_inp, str_out, str_commits = "Passed!","Passed!","Passed!","Passed!"

    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_ki = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.info(str_inp)

    # Check ring-signatures 
    for sig_ind in range(inputs):
        if not (check_sig_clsag_bp1(
                    resp_json,
                    sig_ind,
                    inputs,
                    rows,
                    pubs,
                    masks,
                    message
                )):

            str_inp = ("Verify block_height: "
            + str(h)
            + " tx : "
            + str(txs[i_tx])
            + " ring signature failed")
            settings_df25519.logger_inflation.info(str_inp)
            # raise Exception("ring_signature_failure")

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp_plus(resp_json):
        str_out = (
            "Verify block_height: "
            + str(h)
            + " tx : "
            + str(txs[i_tx])
            + " Bulletproofs failed"
        )
        settings_df25519.logger_inflation.info(str_out)

    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_commits = (
            "Verify block_height: "
            + str(h)
            + " tx : "
            + str(txs[i_tx])
            + " commitments check failed"
        )
        settings_df25519.logger_inflation.info(str_commits)

    return str_ki, str_inp, str_out, str_commits
#--------------------------------------------------------------------------------------------
def check_sig_clsag_bp1(
    resp_json, sig_ind, inputs, rows, pubs, masks, message 
):
    pubs_current = pubs[sig_ind]
    masks_current = masks[sig_ind]

    C_offset = misc_func.get_pseudo_outs_bp1(resp_json, sig_ind)  # C_offset
    ss = resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["s"]
    s_scalar = misc_func.s_to_scalar(ss, rows)
    c1 = Scalar(resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["c1"])
    D = Point(resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["D"])
    I = Point(resp_json["vin"][sig_ind]["key"]["k_image"])

    return check_CLSAG(
        message, s_scalar, c1, D, I, pubs_current, masks_current, C_offset 
    )

#--------------------------------------------------------------------------------------------
def generate_CLSAG(msg, p, P, z, C_offset, C, C_nonzero, Seed=None):
    inv8 = Scalar(8).invert()
    n = len(P)  # ring size

    # Recover the private key index
    l = None
    for i in range(n):
        if P[i] == df25519.G * p and C[i] == df25519.G * z:
            l = i
            break
    if l is None:
        raise IndexError("Private keys must correspond to public keys!")

    # Construct key images
    I = hash_to_point(str(P[l])) * p
    D = hash_to_point(str(P[l])) * z * inv8

    domain0 = "CLSAG_agg_0"
    domain1 = "CLSAG_agg_1"
    domain_round = "CLSAG_round"

    str0 = str(Scalar(0))
    str_agg0_aux = domain0.encode("utf-8").hex()
    str_aux = str0[len(str_agg0_aux) :]
    str_agg0 = str_agg0_aux + str_aux

    str_agg1_aux = domain1.encode("utf-8").hex()
    str_aux = str0[len(str_agg1_aux) :]
    str_agg1 = str_agg1_aux + str_aux

    str_round_aux = domain_round.encode("utf-8").hex()
    str_aux = str0[len(str_round_aux) :]
    str_round = str_round_aux + str_aux

    strP = "".join([str(one_P) for one_P in P])
    strC_nonzero = "".join([str(one_C) for one_C in C_nonzero])

    # Now generate the signature
    mu_P = hash_to_scalar(
        str_agg0 + strP + strC_nonzero + str(I) + str(D) + str(C_offset)
    )
    mu_C = hash_to_scalar(
        str_agg1 + strP + strC_nonzero + str(I) + str(D) + str(C_offset)
    )
    s = [None] * n

    alpha = random_scalar()

    # Private index
    aG = df25519.G * alpha
    aH = hash_to_point(str(P[l])) * alpha
    c = hash_to_scalar(
        str_round + strP + strC_nonzero + str(C_offset) + str(msg) + str(aG) + str(aH)
    )

    i = (l + 1) % n
    if i == 0:
        c1 = copy.copy(c)

    while i != l:
        s[i] = random_scalar()
        cp = c * mu_P
        cc = c * mu_C

        L = s[i] * df25519.G + cp * P[i] + cc * C[i]

        R = s[i] * hash_to_point(str(P[i])) + cp * I + cc * D * Scalar(8)

        str_hash = str_round + strP + strC_nonzero + str(C_offset) + str(msg)
        str_hash += str(L) + str(R)

        c = hash_to_scalar(str_hash)

        i = (i + 1) % n
        if i == 0:
            c1 = copy.copy(c)

    s[l] = alpha - c * (p * mu_P + mu_C * z)

    return s, c1, D
#--------------------------------------------------------------------------------------------
class CLSAG:
    def __init__(self, msg, s, c1, D_aux, I, P, C_nonzero, C_offset):
        self.msg = msg
        self.s = s
        self.c1 = c1 
        self.D_aux = D_aux
        self.I = I 
        self.P = P
        self.C_nonzero = C_nonzero 
        self.C_offset = C_offset
#--------------------------------------------------------------------------------------------
def check_CLSAGs(clsags):
    for c in clsags:
        check_CLSAG(c.msg, c.s, c.c1, c.D_aux, c.I, c.P, c.C_nonzero, c.C_offset)
    return True
#--------------------------------------------------------------------------------------------
def check_CLSAG(msg, s, c1, D_aux, I, P, C_nonzero, C_offset):

    domain0 = "CLSAG_agg_0"
    domain1 = "CLSAG_agg_1"
    domain_round = "CLSAG_round"

    str0 = str(Scalar(0))
    str_agg0_aux = domain0.encode("utf-8").hex()
    str_aux = str0[len(str_agg0_aux) :]
    str_agg0 = str_agg0_aux + str_aux

    str_agg1_aux = domain1.encode("utf-8").hex()
    str_aux = str0[len(str_agg1_aux) :]
    str_agg1 = str_agg1_aux + str_aux

    str_round_aux = domain_round.encode("utf-8").hex()
    str_aux = str0[len(str_round_aux) :]
    str_round = str_round_aux + str_aux

    D = copy.copy(D_aux)

    strP = "".join([str(one_P) for one_P in P])
    strC_nonzero = "".join([str(one_C) for one_C in C_nonzero])

    mu_P = hash_to_scalar(
        str_agg0 + strP + strC_nonzero + str(I) + str(D) + str(C_offset)
    )
    mu_C = hash_to_scalar(
        str_agg1 + strP + strC_nonzero + str(I) + str(D) + str(C_offset)
    )

    c = copy.copy(c1)

    i = 0
    n = len(P)

    while i < n:
        cp = c * mu_P
        cc = c * mu_C

        L = df25519.G.scalar_mult_base(s[i]) + cp * P[i] + cc*(C_nonzero[i] - C_offset)
        R = s[i] * hash_to_point(str(P[i])) + cp * I + Scalar(8) * cc * D 

        str_hash = str_round + strP + strC_nonzero + str(C_offset) + msg
        str_hash += str(L) + str(R)

        c = hash_to_scalar(str_hash)
        i = i + 1

    if (c - c1) == Scalar(0):
        return True

    return False
#--------------------------------------------------------------------------------------------
def get_tx_hash_clsag(resp_json, resp_hex):
    extra_hex = "".join([format(value, "02x") for value in resp_json["extra"]])

    outPk = resp_json["rct_signatures"]["outPk"][-1]

    bp_A = resp_json["rctsig_prunable"]["bp"][0]["A"]
    bp_S = resp_json["rctsig_prunable"]["bp"][0]["S"]
    bp_T1 = resp_json["rctsig_prunable"]["bp"][0]["T1"]
    bp_T2 = resp_json["rctsig_prunable"]["bp"][0]["T2"]
    bp_taux = resp_json["rctsig_prunable"]["bp"][0]["taux"]
    bp_mu = resp_json["rctsig_prunable"]["bp"][0]["mu"]
    L = "".join([str(one_L) for one_L in resp_json["rctsig_prunable"]["bp"][0]["L"]])
    R = "".join([str(one_R) for one_R in resp_json["rctsig_prunable"]["bp"][0]["R"]])
    bp_a = resp_json["rctsig_prunable"]["bp"][0]["a"]
    bp_b = resp_json["rctsig_prunable"]["bp"][0]["b"]
    bp_t = resp_json["rctsig_prunable"]["bp"][0]["t"]

    ph1 = resp_hex.split(extra_hex)[0] + extra_hex
    ph2 = resp_hex.split(extra_hex)[1].split(outPk)[0] + outPk
    ph3 = bp_A + bp_S + bp_T1 + bp_T2 + bp_taux + bp_mu + L + R + bp_a + bp_b + bp_t

    ph1_hash = df25519.cn_fast_hash(ph1)
    ph2_hash = df25519.cn_fast_hash(ph2)
    ph3_hash = df25519.cn_fast_hash(ph3)

    return df25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)
#--------------------------------------------------------------------------------------------
def get_tx_hash_clsag_bp_plus(resp_json, resp_hex):
    extra_hex = "".join([format(value, "02x") for value in resp_json["extra"]])

    outPk = resp_json["rct_signatures"]["outPk"][-1]

    bp_A = resp_json["rctsig_prunable"]["bpp"][0]["A"]
    bp_A1 = resp_json["rctsig_prunable"]["bpp"][0]["A1"]
    bp_B = resp_json["rctsig_prunable"]["bpp"][0]["B"]
    bp_r1 = resp_json["rctsig_prunable"]["bpp"][0]["r1"]
    bp_s1 = resp_json["rctsig_prunable"]["bpp"][0]["s1"]
    bp_d1 = resp_json["rctsig_prunable"]["bpp"][0]["d1"]
    L = "".join([str(one_L) for one_L in resp_json["rctsig_prunable"]["bpp"][0]["L"]])
    R = "".join([str(one_R) for one_R in resp_json["rctsig_prunable"]["bpp"][0]["R"]])

    ph1 = resp_hex.split(extra_hex)[0] + extra_hex
    ph2 = resp_hex.split(extra_hex)[1].split(outPk)[0] + outPk
    ph3 = bp_A + bp_A1 + bp_B + bp_r1 + bp_s1 + bp_d1 + L + R

    ph1_hash = df25519.cn_fast_hash(ph1)
    ph2_hash = df25519.cn_fast_hash(ph2)
    ph3_hash = df25519.cn_fast_hash(ph3)

    return df25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)
