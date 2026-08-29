"""Per-transaction verification dispatcher: routes a tx to the right checker.

Inspects a decoded transaction's version / RingCT type and calls the matching
verifier (v1, MLSAG, CLSAG, range proofs). ``verify_tx`` returns True iff every
check passes. Failures are logged via ``settings_df25519`` loggers.

This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether
        (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""


from mic.common import com_db
from mic.common import misc_func
from mic.v1 import check_v1
from mic.mlsag import check_mlsag
from mic.clsag import check_clsag
from mic.rangeproofs import check_rangeproofs
from mic.common.df25519 import Point
from mic.common import settings_df25519
def verify_tx_with_string(h, tx_to_check, i_tx=0, details=0):
    if len(tx_to_check) >= 1:
        txs = tx_to_check
        resp_json, resp_hex = com_db.get_tx(tx_to_check, i_tx)
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json["vout"])

    if resp_json["version"] == 1:
        if "gen" in resp_json["vin"][0]:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            settings_df25519.logger_basic.info(
                "Miner transaction. Total amount mined and transaction fees: %s XMR.",
                amount / 1e12,
            )
        else:
            str_ki, str_inp, str_out, str_commit = check_v1.ring_sig_correct(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )

    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2:  # RCTTypeSimple and RCTTypeFull
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 3 or type_tx == 4:  # RCTTypeBulletproof and RCTTypeBulletproof2
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct_bp1(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 5:  # RCTTypeCLSAG
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp1(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 6:  # RCTTypeBulletproofPlus
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp_plus(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )

        elif type_tx == 0:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            settings_df25519.logger_basic.info(
                "Miner transaction. Total amount mined and transaction fees: %s XMR.",
                amount / 1e12,
            )
        else:
            raise Exception

    return str_ki, str_inp, str_out, str_commit


# --------------------------------------------------------------------------------------------
def verify_tx(tx_to_check, i_tx=0):
    if len(tx_to_check) >= 1:
        txs = tx_to_check
        resp_json, resp_hex = com_db.get_tx(tx_to_check, i_tx)
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json["vout"])

    if resp_json["version"] == 1:
        if "gen" in resp_json["vin"][0]:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            settings_df25519.logger_basic.info(
                "Miner transaction. Total amount mined and transaction fees: %s XMR.",
                amount / 1e12,
            )
        else:
            if not verify_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False

    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2:  # RCTTypeSimple and RCTTypeFull
            if not verify_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 3 or type_tx == 4:  # RCTTypeBulletproof and RCTTypeBulletproof2
            if not verify_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 5:  # RCTTypeCLSAG
            if not verify_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 6:  # RCTTypeBulletproofPlus
            if not verify_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False

        elif type_tx == 0:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            settings_df25519.logger_basic.info(
                "Miner transaction. Total amount mined and transaction fees: %s XMR.",
                amount / 1e12,
            )
        else:
            raise Exception

    return True


# --------------------------------------------------------------------------------------------
def verify_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    tx_prefix = check_v1.get_tx_prefix_hash(resp_json, resp_hex)

    if not check_v1.check_balance(inputs, outputs, resp_json):
        str_res = "Verification of balance v1 failed. See tx: " + str(txs[i_tx])
        settings_df25519.logger_inflation.critical(str_res)
        return False

    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    pubs, _ = misc_func.get_members_and_masks_in_rings(resp_json)

    for sig_ind in range(inputs):
        if not check_v1.check_v1(resp_json, resp_hex, sig_ind, pubs, tx_prefix):
            str_res = "Verify tx " + str(txs[i_tx]) + " ring signature failed"
            settings_df25519.logger_inflation.critical(str_res)
            return False

    return True


# --------------------------------------------------------------------------------------------
def verify_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_mlsag.get_tx_hash_mlsag(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures
    for sig_ind in range(inputs):
        if not (
            check_mlsag.check_sig_mlsag(resp_json, sig_ind, inputs, rows, pubs, masks, message)
        ):

            str_res = "Verify " + " tx : " + str(txs[i_tx]) + " ring signature failed"
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    for sig_out in range(outputs):
        if not check_rangeproofs.check_sig_borromean(resp_json, sig_out):
            str_res = "Verify " + " tx : " + str(txs[i_tx]) + " Borromean failed"
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check commitments
    if not check_rangeproofs.check_commitments(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " commitments check failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True


# --------------------------------------------------------------------------------------------
def verify_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_mlsag.get_tx_hash_bp1(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures
    for sig_ind in range(inputs):
        if not (
            check_mlsag.check_sig_mlsag_bp1(resp_json, sig_ind, inputs, rows, pubs, masks, message)
        ):

            str_res = "Verify " + " tx : " + str(txs[i_tx]) + " ring signature failed"
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp1(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " Borromean failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " commitments check failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True


# --------------------------------------------------------------------------------------------
def verify_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_clsag.get_tx_hash_clsag(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures
    for sig_ind in range(inputs):
        if not (
            check_clsag.check_sig_clsag_bp1(resp_json, sig_ind, inputs, rows, pubs, masks, message)
        ):

            str_res = "Verify " + " tx : " + str(txs[i_tx]) + " ring signature failed"
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp1(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " Bulletproofs failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " commitments check failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True


# --------------------------------------------------------------------------------------------
def verify_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):

    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_clsag.get_tx_hash_clsag_bp_plus(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures
    for sig_ind in range(inputs):
        if not (
            check_clsag.check_sig_clsag_bp1(resp_json, sig_ind, inputs, rows, pubs, masks, message)
        ):

            str_res = "Verify " + " tx : " + str(txs[i_tx]) + " ring signature failed"
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp_plus(resp_json):
        str_res = "Verify " + " tx : " + str(txs[i_tx]) + " Bulletproofs failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = "Verify tx " + str(txs[i_tx]) + " commitments check failed"
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True


# --------------------------------------------------------------------------------------------
# Check Points and Scalars
# --------------------------------------------------------------------------------------------
def check_points(points):
    not_in_curve = []
    for p in points:
        if not p.on_curve():
            not_in_curve.append(p)
    if len(not_in_curve) == 0:
        return True
    else:
        return not_in_curve

    return False


# --------------------------------------------------------------------------------------------
def check_scalars(scalars):
    not_canonical = []
    for s in scalars:
        if not s.is_canonical():
            not_canonical.append(s)
    if len(not_canonical) == 0:
        return True
    else:
        return not_canonical

    return False


# --------------------------------------------------------------------------------------------
def precheck_tx(tx_to_check, i_tx=0):
    if len(tx_to_check) >= 1:
        txs = tx_to_check
        resp_json, resp_hex = com_db.get_tx(tx_to_check, i_tx)
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json["vout"])

    if resp_json["version"] == 1:
        precheck_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs)

    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2:  # RCTTypeSimple and RCTTypeFull
            if not precheck_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 3 or type_tx == 4:  # RCTTypeBulletproof and RCTTypeBulletproof2
            if not precheck_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 5:  # RCTTypeCLSAG
            if not precheck_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 6:  # RCTTypeBulletproofPlus
            if not precheck_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        else:
            raise Exception

    return True


# --------------------------------------------------------------------------------------------
def precheck_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs):

    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)

    pubs, _ = misc_func.get_members_and_masks_in_rings(resp_json)

    points_to_check = []
    for pi in pubs:
        for i in pi:
            points_to_check.append(i)

    c = check_points(points_to_check)

    if not c:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([c])
        settings_df25519.logger_precheck.critical(str_res)

    return True


# --------------------------------------------------------------------------------------------
def precheck_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)
    points_to_check = []

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_precheck.critical(str_res)

    for pi in pubs:
        for i in pi:
            points_to_check.append(i)

    for mi in masks:
        for i in mi:
            points_to_check.append(i)

    ci = check_points(points_to_check)

    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    # Check rangeproofs
    points_to_check = []
    scalars_to_check = []
    for sig_out in range(outputs):
        P1, P2, bbee, bbs0, bbs1 = check_rangeproofs.get_borromean_vars(resp_json, sig_out)
        points_to_check = P1 + P2
        scalars_to_check = [bbee] + bbs0 + bbs1

        ci = check_points(points_to_check)
        if not ci:
            str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
            settings_df25519.logger_precheck.critical(str_res)

        si = check_scalars(scalars_to_check)
        if not si:
            str_res = "tx : " + str(txs[i_tx]) + ", scalars: " + str([si])
            settings_df25519.logger_precheck.critical(str_res)

    points_to_check = []
    # Check commitments
    if "pseudoOuts" in resp_json["rct_signatures"]:
        for i in range(len(resp_json["rct_signatures"]["pseudoOuts"])):
            points_to_check.append(Point(resp_json["rct_signatures"]["pseudoOuts"][i]))
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            points_to_check.append(Point(resp_json["rct_signatures"]["outPk"][i]))

    cc = check_points(points_to_check)
    if not cc:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([cc])
        settings_df25519.logger_precheck.critical(str_res)

    return True


# --------------------------------------------------------------------------------------------
def precheck_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)
    points_to_check = []

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_precheck.critical(str_res)

    for pi in pubs:
        for i in pi:
            points_to_check.append(i)

    for mi in masks:
        for i in mi:
            points_to_check.append(i)

    ci = check_points(points_to_check)

    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    # Check rangeproofs
    points_to_check = []
    scalars_to_check = []
    proofs = check_rangeproofs.get_vars_bp1(resp_json)
    V, A, S, T1, T2, taux, mu, L, R, a, b, t = proofs
    points_to_check += V.points + [A] + [S] + [T1] + [T2] + L.points + R.points
    scalars_to_check = [taux] + [mu] + [a] + [b] + [t]

    ci = check_points(points_to_check)
    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    si = check_scalars(scalars_to_check)
    if not si:
        str_res = "tx : " + str(txs[i_tx]) + ", scalars: " + str([si])
        settings_df25519.logger_precheck.critical(str_res)

    # Check commitments
    points_to_check = []
    for i in range(len(resp_json["rctsig_prunable"]["pseudoOuts"])):
        points_to_check.append(Point(resp_json["rctsig_prunable"]["pseudoOuts"][i]))
    for i in range(len(resp_json["rct_signatures"]["outPk"])):
        points_to_check.append(Point(resp_json["rct_signatures"]["outPk"][i]))

    cc = check_points(points_to_check)
    if not cc:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([cc])
        settings_df25519.logger_precheck.critical(str_res)

    return True


# --------------------------------------------------------------------------------------------
def precheck_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)
    points_to_check = []

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_precheck.critical(str_res)

    for pi in pubs:
        for i in pi:
            points_to_check.append(i)

    for mi in masks:
        for i in mi:
            points_to_check.append(i)

    ci = check_points(points_to_check)

    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    # Check rangeproofs
    points_to_check = []
    scalars_to_check = []
    proofs = check_rangeproofs.get_vars_bp1(resp_json)
    V, A, S, T1, T2, taux, mu, L, R, a, b, t = proofs
    points_to_check += V.points + [A] + [S] + [T1] + [T2] + L.points + R.points
    scalars_to_check = [taux] + [mu] + [a] + [b] + [t]

    ci = check_points(points_to_check)
    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    si = check_scalars(scalars_to_check)
    if not si:
        str_res = "tx : " + str(txs[i_tx]) + ", scalars: " + str([si])
        settings_df25519.logger_precheck.critical(str_res)

    # Check commitments
    points_to_check = []
    for i in range(len(resp_json["rctsig_prunable"]["pseudoOuts"])):
        points_to_check.append(Point(resp_json["rctsig_prunable"]["pseudoOuts"][i]))
    for i in range(len(resp_json["rct_signatures"]["outPk"])):
        points_to_check.append(Point(resp_json["rct_signatures"]["outPk"][i]))

    cc = check_points(points_to_check)
    if not cc:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([cc])
        settings_df25519.logger_precheck.critical(str_res)

    return True


# --------------------------------------------------------------------------------------------
def precheck_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)
    points_to_check = []

    # Check key images
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_precheck.critical(str_res)

    for pi in pubs:
        for i in pi:
            points_to_check.append(i)

    for mi in masks:
        for i in mi:
            points_to_check.append(i)

    ci = check_points(points_to_check)

    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    # Check rangeproofs
    points_to_check = []
    scalars_to_check = []
    proofs = check_rangeproofs.get_vars_bp_plus(resp_json)
    V, A, A1, B, r1, s1, d1, L, R = proofs
    points_to_check += V.points + [A] + [A1] + [B] + L.points + R.points
    scalars_to_check = [r1] + [s1] + [d1]

    ci = check_points(points_to_check)
    if not ci:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([ci])
        settings_df25519.logger_precheck.critical(str_res)

    si = check_scalars(scalars_to_check)
    if not si:
        str_res = "tx : " + str(txs[i_tx]) + ", scalars: " + str([si])
        settings_df25519.logger_precheck.critical(str_res)

    # Check commitments
    points_to_check = []
    for i in range(len(resp_json["rctsig_prunable"]["pseudoOuts"])):
        points_to_check.append(Point(resp_json["rctsig_prunable"]["pseudoOuts"][i]))
    for i in range(len(resp_json["rct_signatures"]["outPk"])):
        points_to_check.append(Point(resp_json["rct_signatures"]["outPk"][i]))

    cc = check_points(points_to_check)
    if not cc:
        str_res = "tx : " + str(txs[i_tx]) + ", points: " + str([cc])
        settings_df25519.logger_precheck.critical(str_res)

    return True
