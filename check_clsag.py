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
from dumber25519 import Scalar, Point, PointVector, ScalarVector,hash_to_point,hash_to_scalar,random_scalar
import copy
import multiprocessing
import check_rangeproofs
from concurrent.futures import as_completed, ProcessPoolExecutor
import settings



def ring_sig_correct_bp1(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details):

    rows = len(resp_json['vin'][0]['key']['key_offsets'])
    message = get_tx_hash_clsag(resp_json,resp_hex)
    pubs = misc_func.get_members_in_ring(txs,i_tx,inputs,rows)
    masks = misc_func.get_masks_in_ring(resp_json,inputs,rows)

### Signature index
    str_ki = []
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        str_ki.append(misc_func.verify_ki(Iv))
    # time_ver = time.time()

    y = []
    for sig_ind in range(inputs):
        try:
            with ProcessPoolExecutor() as exe:
                # args = (resp_json,sig_ind,inputs,rows,pubs,masks,message,details)
                y.append(exe.submit(check_sig_clsag_bp1,resp_json,sig_ind,inputs,rows,pubs,masks,message,details))
            # y.append(multiprocessing.Process(target=check_sig_mlsag, args=args))
            # y[sig_ind].start()
            # res = check_sig_clsag_bp1(resp_json,sig_ind,inputs,rows,pubs,masks,message,details)
            
        except:
            print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx]) + ' ring signature failed')

    str_inp = []
    for res in as_completed(y):
        str_inp.append(res.result())



    # str_out = check_rangeproofs.check_sig_bp1(resp_json)
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

    # print('Total time verification', time.time() - time_ver)
    # print('Total time verification tx', time.time() - time_tx)
    return str_ki, str_inp,str_out, str_commits

def check_sig_clsag_bp1(resp_json,sig_ind,inputs,rows,pubs,masks,message,details):
    pubs_current = pubs[sig_ind]
    masks_current = masks[sig_ind] 

    C_offset = misc_func.get_pseudo_outs_bp1(resp_json,sig_ind) #C_offset
    ss = resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["s"]
    s_scalar = misc_func.s_to_scalar(ss,rows)
    c1 = Scalar(resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["c1"])
    D = Point(resp_json["rctsig_prunable"]["CLSAGs"][sig_ind]["D"])
# PK = misc_func.point_matrix_mg(pubs[sig_ind],masks[sig_ind],pseudoOuts)
    I = Point(resp_json["vin"][sig_ind]["key"]["k_image"])


    verified,str_out = check_CLSAG(message, s_scalar, c1, D, I, pubs_current, masks_current, C_offset,details)
    if verified == False:
        print('Signatures dont match! Verify this block')
        print('Potential inflation in CLSAG ring signature! Please verify what is happening!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in CLSAG ring signature! Please verify what is happening!') 
        raise Exception('ring_signature_failure')

    return str_out



def generate_CLSAG(msg,p,P,z,C_offset,C,C_nonzero,Seed=None):
    inv8 = Scalar(8).invert()
    n = len(P) # ring size

    # Recover the private key index
    l = None
    for i in range(n):
        if P[i] == dumber25519.G*p and C[i] == dumber25519.G*z:
            l = i
            break
    if l is None:
        raise IndexError('Private keys must correspond to public keys!')

    # Construct key images
    I = hash_to_point(str(P[l]))*p
    D = hash_to_point(str(P[l]))*z*inv8

    domain0 = 'CLSAG_agg_0' 
    domain1 = 'CLSAG_agg_1' 
    domain_round = 'CLSAG_round'

    str0 = str(Scalar(0))
    str_agg0_aux = domain0.encode("utf-8").hex()
    str_aux = str0[len(str_agg0_aux):]
    str_agg0 = str_agg0_aux + str_aux

    str_agg1_aux = domain1.encode("utf-8").hex()
    str_aux = str0[len(str_agg1_aux):]
    str_agg1 = str_agg1_aux + str_aux

    str_round_aux = domain_round.encode("utf-8").hex()
    str_aux = str0[len(str_round_aux):]
    str_round = str_round_aux + str_aux

    strP = ''
    for i in range(len(P)):
        strP += str(P[i])

    strC_nonzero = ''
    for i in range(len(C_nonzero)):
        strC_nonzero += str(C_nonzero[i])

    # Now generate the signature
    mu_P = hash_to_scalar(str_agg0+strP+strC_nonzero+str(I)+str(D)+str(C_offset))
    mu_C = hash_to_scalar(str_agg1+strP+strC_nonzero+str(I)+str(D)+str(C_offset))
    s = [None]*n

    alpha = random_scalar()

    # Private index
    aG = dumber25519.G*alpha
    aH = hash_to_point(str(P[l]))*alpha
    c = hash_to_scalar(str_round+strP+strC_nonzero+str(C_offset)+str(msg)+str(aG)+str(aH))
   
    i = (l+1) % n
    if (i==0):
        c1 = copy.copy(c)

    while (i!=l):
        s[i] = random_scalar()
        cp = c*mu_P
        cc = c*mu_C

        L = s[i]*dumber25519.G + cp*P[i]+ cc*C[i]

        R = s[i]*hash_to_point(str(P[i])) + cp*I + cc*D*Scalar(8)

        str_hash = str_round+strP+strC_nonzero+str(C_offset)+str(msg)
        str_hash += str(L) + str(R)

        c = hash_to_scalar(str_hash)

        i = (i+1) % n
        if i==0:
            c1 = copy.copy(c)

    s[l] = alpha - c*(p*mu_P+mu_C*z)

    import ipdb;ipdb.set_trace()
    return s,c1,D


def check_CLSAG(msg, s, c1, D_aux,I, P, C_nonzero, C_offset,details):

    str_out = '\n'
    str_out += '--------------------------------------------------------\n'
    str_out += '-------------Checking CLSAG Ring Signature--------------\n'
    str_out += '--------------------------------------------------------\n'
    str_out += 'Arguments of check_ring_signature: '
    str_out += 'Prefix: ' + str(msg)
    str_out += '\n'
    str_out += 'Key_image: ' + str(I)
    str_out += '\n'
    str_out += 'Public keys: ' + str(P)
    str_out += '\n'
    str_out += 'Signature c1: ' + str(c1)
    str_out += '\n'
    str_out += 'Signature s: ' + str(s)
    str_out += '\n'

    
    domain0 = 'CLSAG_agg_0' 
    domain1 = 'CLSAG_agg_1' 
    domain_round = 'CLSAG_round'

    str0 = str(Scalar(0))
    str_agg0_aux = domain0.encode("utf-8").hex()
    str_aux = str0[len(str_agg0_aux):]
    str_agg0 = str_agg0_aux + str_aux

    str_agg1_aux = domain1.encode("utf-8").hex()
    str_aux = str0[len(str_agg1_aux):]
    str_agg1 = str_agg1_aux + str_aux

    str_round_aux = domain_round.encode("utf-8").hex()
    str_aux = str0[len(str_round_aux):]
    str_round = str_round_aux + str_aux

    D = copy.copy(D_aux)

    strP = ''
    for i in range(len(P)):
        strP += str(P[i])

    strC_nonzero = ''
    for i in range(len(C_nonzero)):
        strC_nonzero+= str(C_nonzero[i])

    mu_P = hash_to_scalar(str_agg0+strP+strC_nonzero+str(I)+str(D)+str(C_offset))
    mu_C = hash_to_scalar(str_agg1+strP+strC_nonzero+str(I)+str(D)+str(C_offset))

    c = copy.copy(c1)

    i = 0
    n = len(P)

    while (i<n):
        cp = c*mu_P
        cc = c*mu_C

        L = s[i]*dumber25519.G + cp*P[i]+ cc*(C_nonzero[i] - C_offset )
        R = s[i]*hash_to_point(str(P[i])) + cp*I + cc*D*Scalar(8)

        str_hash = str_round+strP+strC_nonzero+str(C_offset)+msg
        str_hash += str(L) + str(R)

        c = hash_to_scalar(str_hash)
        i = i+1

    c_final = c - c1

    str_out += 'Calculating c_final = c - c1 :' 
    str_out += '\n'
    res = (c-c1) == Scalar(0)
    str_out += str(c-c1)
    str_out += '\n'
    if res:
        str_out += 'Transaction is valid. The signature matches the data.'
    else:
        str_out += 'Transaction is invalid. The signature does not match the data.'

    str_out += '\n'
    str_out += '--------------------------------------------------------'
    str_out += '\n'
    return res, str_out




def get_tx_hash_clsag(resp_json,resp_hex):
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



