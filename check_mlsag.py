"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import json
import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector
import copy
import multiprocessing
import check_rangeproofs
from concurrent.futures import as_completed, ProcessPoolExecutor


def ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details):

        rows = len(resp_json['vin'][0]['key']['key_offsets'])
        message = get_tx_hash_mlsag(resp_json,resp_hex)
        pubs = misc_func.get_members_in_ring(txs,i_tx,inputs,rows)
        masks = misc_func.get_masks_in_ring(resp_json,inputs,rows)
        str_ki = []
        for sig_ind in range(inputs):
            Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
            str_ki.append(misc_func.verify_ki(Iv))

        y = []
        for sig_ind in range(inputs):
            try:
                with ProcessPoolExecutor() as exe:
                    y.append(exe.submit(check_sig_mlsag,resp_json,sig_ind,inputs,rows,pubs,masks,message,details))
                
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx]) + ' ring signature failed')

        str_inp = []
        for res in as_completed(y):
            str_inp.append(res.result())

        x = []
        for sig_ind in range(outputs):
            try:
                with ProcessPoolExecutor() as exe:
                    x.append(exe.submit(check_rangeproofs.check_sig_Borromean, resp_json,sig_ind))
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' Borromean failed')

        str_out= []
        for res in as_completed(x):
            str_out.append(res.result())

        try:
            str_commits = check_rangeproofs.check_commitments(resp_json)
        except:
            print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' commitments check failed')

        return str_ki, str_inp,str_out, str_commits


def ring_sig_correct_bp1(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details):

        rows = len(resp_json['vin'][0]['key']['key_offsets'])
        message = get_tx_hash_bp1(resp_json,resp_hex)
        pubs = misc_func.get_members_in_ring(txs,i_tx,inputs,rows)
        masks = misc_func.get_masks_in_ring(resp_json,inputs,rows)
        str_ki = []
        for sig_ind in range(inputs):
            Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
            str_ki.append(misc_func.verify_ki(Iv))

        y = []
        for sig_ind in range(inputs):
            try:
                with ProcessPoolExecutor() as exe:
                    y.append(exe.submit(check_sig_mlsag_bp1,resp_json,sig_ind,inputs,rows,pubs,masks,message,details))
                
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx]) + ' ring signature failed')

        str_inp = []
        for res in as_completed(y):
            str_inp.append(res.result())

        x = []
        for sig_ind in range(1):
            try:
                with ProcessPoolExecutor() as exe:
                    x.append(exe.submit(check_rangeproofs.check_sig_bp1, resp_json))
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' Bulletproofs failed')

        str_out= []
        for res in as_completed(x):
            str_out.append(res.result())



        try:
            str_commits = check_rangeproofs.check_commitments_bp1(resp_json)
        except:
            print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' commitments check failed')

        return str_ki, str_inp,str_out, str_commits

def check_sig_mlsag(resp_json,sig_ind,inputs,rows,pubs,masks,message,details):
    pseudoOuts = misc_func.get_pseudo_outs(resp_json,sig_ind)
    sss = resp_json["rctsig_prunable"]["MGs"][sig_ind]["ss"]
    ss_scalar = misc_func.ss_to_scalar(sss,rows,2)

    cc = Scalar(resp_json["rctsig_prunable"]["MGs"][sig_ind]["cc"])

    PK = misc_func.point_matrix_mg(pubs[sig_ind],masks[sig_ind],pseudoOuts)

    IIv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])



    verified,str_out = check_MLSAG(message,PK, IIv, cc, ss_scalar,details)
    if verified == False:
        print('Signatures dont match! Verify this block')
        print('Potential inflation in MLSAG ring signature! Please verify what is happening!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in MLSAG ring signature! Please verify what is happening!') 
        raise Exception('ring_signature_failure')

    return str_out

def check_sig_mlsag_bp1(resp_json,sig_ind,inputs,rows,pubs,masks,message,details):
    pseudoOuts = misc_func.get_pseudo_outs_bp1(resp_json,sig_ind)
    sss = resp_json["rctsig_prunable"]["MGs"][sig_ind]["ss"]
    ss_scalar = misc_func.ss_to_scalar(sss,rows,2)

    cc = Scalar(resp_json["rctsig_prunable"]["MGs"][sig_ind]["cc"])

    PK = misc_func.point_matrix_mg(pubs[sig_ind],masks[sig_ind],pseudoOuts)

    IIv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])



    verified,str_out = check_MLSAG(message,PK, IIv, cc, ss_scalar,details)
    if verified == False:
        print('Signatures dont match! Verify this block')
        print('Potential inflation in MLSAG ring signature! Please verify what is happening!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in MLSAG ring signature! Please verify what is happening!') 
        raise Exception('ring_signature_failure')

    return str_out

def generate_MLSAG(m,PK,sk,index):
    rows = len(PK)
    cols = len(PK[0])
    msg0 = ''
    msg0 += str(m)

    alpha0 = dumber25519.random_scalar()
    aG0 = alpha0 * dumber25519.G
    aHP = alpha0 * dumber25519.hash_to_point(str(PK[index][0]))
    msg0 += str(PK[index][0])
    msg0 += str(aG0)
    msg0 += str(aHP)

    alpha1 = dumber25519.random_scalar()
    aG1 = alpha1 * dumber25519.G
    msg0 += str(PK[index][1])
    msg0 += str(aG1)

    I0 = sk[0]*dumber25519.hash_to_point(str(PK[index][0]))

    c_old = dumber25519.hash_to_scalar(msg0)
    i = (index + 1) % rows
    if i==0:
        cc = copy.copy(c_old)
    
    ss = misc_func.scalar_matrix(rows,cols,0) 

    while (i!=index):
        msg = ''
        msg += str(m)

        ss[i][0] = dumber25519.random_scalar() 
        ss[i][1] = dumber25519.random_scalar() 

        L1 = ss[i][0]*dumber25519.G + c_old*PK[i][0]
        R = ss[i][0]*dumber25519.hash_to_point(str(PK[i][0]))+c_old*I0
        msg += str(PK[i][0])
        msg += str(L1)
        msg += str(R)

        L2 = ss[i][1]*dumber25519.G + c_old*PK[i][1]
        msg += str(PK[i][1])
        msg += str(L2)

        c_old = dumber25519.hash_to_scalar(msg)
        i = (i+1)%rows
        if i==0:
            cc = copy.copy(c_old)

    ss[index][0] = alpha0 - c_old*sk[0]
    ss[index][1] = alpha1 - c_old*sk[1] 

    return ss, cc, I0


def check_MLSAG(m,PK, I, c, ss,details=0):
    rows = len(PK)
    cols = len(PK[0])
    c_old = copy.copy(c)

    str_out = '\n'
    str_out += '--------------------------------------------------------\n'
    str_out += '-------------Checking MLSAG Ring Signature--------------\n'
    str_out += '--------------------------------------------------------\n'
    str_out += 'Arguments of check_ring_signature: '
    str_out += 'Prefix: ' + str(m)
    str_out += '\n'
    str_out += 'Key_image: ' + str(I)
    str_out += '\n'
    str_out += 'Public keys: ' + str(PK)
    str_out += '\n'
    str_out += 'Signature ss: ' + str(ss)
    str_out += '\n'
    str_out += 'Signature c: ' + str(c)
    str_out += '\n'

    i = 0
    msg = ''
    msg += str(m)
    while i < rows:
        toHash = ''
        toHash += str(m)

        str_out += 'Calculating L1 = ss[i][0] * G + ci * P[i][0]   for index = ' + str(i)
        str_out += '\n'
        str_out += 'Calculating R = ss[i][0] * H(P[i][0]) + ci * I   for index = ' + str(i)
        str_out += '\n'

        L1 = ss[i][0]*dumber25519.G + c_old*PK[i][0]
        R = ss[i][0]*dumber25519.hash_to_point(str(PK[i][0]))+c_old*I

        str_out += 'L1 calculated for index = ' + str(i)
        str_out += '\n'
        str_out += str(L1)
        str_out += '\n'
        str_out += 'R calculated for index = ' + str(i)
        str_out += '\n'
        str_out += str(R)
        str_out += '\n'

        toHash += str(PK[i][0])
        toHash += str(L1)
        toHash += str(R)

        L2 = ss[i][1]*dumber25519.G + c_old*PK[i][1]
        toHash += str(PK[i][1])
        toHash += str(L2)

        str_out += 'Calculating L2 = ss[i][1] * G + ci * P[i][1]   for index = ' + str(i)
        str_out += '\n'
        str_out += 'L2 calculated for index = ' + str(i)
        str_out += '\n'
        str_out += str(L2)
        str_out += '\n'

        c_old = dumber25519.hash_to_scalar(toHash)
        i = i + 1
        str_out += 'Calculating c_old: ' + str(c_old)
        str_out += '\n'

    
    str_out += 'Calculating c_old - c :' 
    str_out += '\n'
    res = (c_old-c) == Scalar(0)
    str_out += str(c_old-c)
    str_out += '\n'
    if res:
        str_out += 'Transaction is valid. The signature matches the data.'
    else:
        str_out += 'Transaction is invalid. The signature does not match the data.'

    str_out += '\n'
    str_out += '--------------------------------------------------------'
    str_out += '\n'
    return res, str_out


def get_tx_hash_mlsag(resp_json,resp_hex):
    extra_hex = ''
    for i in range(len(resp_json['extra'])):
        extra_hex += format(resp_json["extra"][i],'02x')

    ss = resp_json["rctsig_prunable"]["MGs"][0]["ss"]
    asig = resp_json["rctsig_prunable"]["rangeSigs"][0]["asig"]

    ph1 = resp_hex.split(extra_hex)[0] + extra_hex
    ph2 = resp_hex.split(extra_hex)[1].split(asig)[0]
    ph3 = resp_hex.split(resp_json["rct_signatures"]["outPk"][-1])[1].split(ss[0][0])[0]

    ph1_hash = dumber25519.cn_fast_hash(ph1)
    ph2_hash = dumber25519.cn_fast_hash(ph2)
    ph3_hash = dumber25519.cn_fast_hash(ph3)

    return dumber25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)

def get_tx_hash_bp1(resp_json,resp_hex):
    extra_hex = ''
    for i in range(len(resp_json['extra'])):
        extra_hex += format(resp_json["extra"][i],'02x')

    outPk = resp_json["rct_signatures"]["outPk"][-1]

    # import ipdb;ipdb.set_trace()
    L,R = '',''
    bp_A = resp_json["rctsig_prunable"]["bp"][0]["A"]
    bp_S = resp_json["rctsig_prunable"]["bp"][0]["S"]
    bp_T1 = resp_json["rctsig_prunable"]["bp"][0]["T1"]
    bp_T2 = resp_json["rctsig_prunable"]["bp"][0]["T2"]
    bp_taux = resp_json["rctsig_prunable"]["bp"][0]["taux"]
    bp_mu = resp_json["rctsig_prunable"]["bp"][0]["mu"]
    for i in range(len(resp_json["rctsig_prunable"]["bp"][0]["L"])):
        L += str(resp_json["rctsig_prunable"]["bp"][0]["L"][i])
    for i in range(len(resp_json["rctsig_prunable"]["bp"][0]["R"])):
        R += str(resp_json["rctsig_prunable"]["bp"][0]["R"][i])
    bp_a = resp_json["rctsig_prunable"]["bp"][0]["a"]
    bp_b = resp_json["rctsig_prunable"]["bp"][0]["b"]
    bp_t = resp_json["rctsig_prunable"]["bp"][0]["t"]

    ph1 = resp_hex.split(extra_hex)[0] + extra_hex
    ph2 = resp_hex.split(extra_hex)[1].split(outPk)[0]+outPk
    ph3 = bp_A+bp_S+bp_T1+bp_T2+bp_taux+bp_mu+L+R+bp_a+bp_b+bp_t


    ph1_hash = dumber25519.cn_fast_hash(ph1)
    ph2_hash = dumber25519.cn_fast_hash(ph2)
    ph3_hash = dumber25519.cn_fast_hash(ph3)

    return dumber25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)
