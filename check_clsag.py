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
        # import ipdb;ipdb.set_trace()
        try:
            with ProcessPoolExecutor() as exe:
                x.append(exe.submit(check_rangeproofs.check_sig_bp1, resp_json))
                # x.append(multiprocessing.Process(target=check_rangeproofs.check_sig_Borromean, args=(resp_json,sig_ind, )))
                # x[sig_ind].start()
        except:
            print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' Borromean failed')

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



# msg = str('612ebe1b1bfdd4f49732afedc43f4c815f899e190f316eda75fad5423e53b8e6')
# p = Scalar('073d1d6d6d3ec1b47b03b40d4fd9fec97fca4b61ed49a66bb32e818b5d9c710f')
# z = Scalar('64aca5a5c70ff73ef3a192f8286efb1353eb8c642ef96d8c263d8b4ea2259b0c')
# C_offset = Point('feae5544786270b394a8f34f753d550be92a318c291926b7d9bfa7fb4cde3745')
# l = 1

# P = PointVector([ Point('af837eefa0de5135777b7cc52f8a68d8a883b22f156bf0e04873548b9caa8edb'),Point('1e9e346d687fc94c102a0ee70d050ba70d8135a366581a98e2c45e8926e8ed83'),Point('267b7f48f760219278443f40d5edb097d82b1aa7e7e6a6cae084f19d18f7b3c7'),Point('88afa48a95ce58cdc9eb988abdc9c3b9226efe1ddd12b6ab0a4afec3be6faee7'),Point('9be7a0ea0cee158f788f0ab788e0ec3db67f2a288a8a64c0e1d85056d06ba908'),Point('82f204a77a869456afc5a345a1770dc1beed379b2bfb3c331294220d6d9ca0c6'),Point('99b32f89d6b860ad58109829b1eed052188a1d6a8ba1e965ae4b82fae7f02411'),Point('abddfd5f34fa96cfc93058feb189e6433cbdcdbfd9e13286d9109448c142e720'),Point('7f23a1a5680516f6f3056ffff709e1780d1e5fa826ebfd097b6f0fd98e758cc3'),Point('5ad9278b0be168f15b9fa5c68537c68f3f37f03d7999a1e6e8f4e28882dc4320'),Point('993f2ef0adc11ddd1f7414f5049cf94cb3742423b5309bc9944e0752fcdcf342'),])
 
# C = PointVector([ Point('de50d6aabc7bd68eff67bded347d494140d8ed0c12a6785a0ba3dad497b24c86'),Point('a1ec7c218ae64b7e0dad3330ab1e1abd7902aca944992b4ba8caa9201682fa07'),Point('6ca7bd3e3863ea0a8710fe893b8a27f0f4c834d7a82699db1711eaacab079f24'),Point('2f07ff1641083850605c04059e17aad0241e10b65994f1ffcc34f3e2c80e716f'),Point('d4f2e9080afe0296164554e5846cea8955b489af4f8bb531a8e34a1f80e7a02b'),Point('1172a23df246f5973b12541d2068afa16159a1fdc421aab27fca6b9fab09bfab'),Point('88f1b21020e38d50c7fd98feefc6253291613db00129654d786320318a6880d4'),Point('8522ddaae47f142fa34654d828674b51357e74c75cbe55501b600806c5506576'),Point('faab64f49cac9dcf53cb0de21a41be20a3234369b1b5609305fa737f4a9413ce'),Point('e751f0ef44cdeb6d5e5821e8013e7de02e9522651b8b9763a304468979b86008'),Point('d6f3ab5d6f9bf2569c12f7fa800dbfe66a69e406db7e6318cfb26ab1e966d262'),])
 
# C_nonzero = PointVector([ Point('ef056230343b70feb26fc4c3cde31c96ec6481f9815893240c72cf2e55a20678'),Point('0fcba4f8a5794d45c0bb0c9bae361857285a05a72704f0af27319dfbb02e5868'),Point('0b77f1a2395294b40cf5a3b1d7e1d9e3615e3262ca2e2cd5e8e4c975d01d4ff4'),Point('94fe96babf8986539db8ab69a219733c5280d5d2b5d7d64af70f04fb66eb402e'),Point('b308f21f6749df01857bd39829f1c84beed823a569577a78f447f1cbdd7f9852'),Point('b8178cc7aff509d42872eec29e0f089c2128f9a2e7fd3a0494e20cad6216cf47'),Point('d148d43672a326e22a2374d9c865cabfbeb555d7cb7e5eb9899c9c4fecb05936'),Point('cd478010293e2f298f3b21243e14fdb4f1806ae030b3c3a65585e60ad2c61a56'),Point('166d0ebf687ccb8a459c407261be109304eeef9f89e8cb6bd40b5f8515f9c128'),Point('eb90be4a8d3810d05113e2eec14bb7e0c3d244a974a1732e19c81716042a7984'),Point('43f3aaf9d2f142621661985916cd8d7e7e9c1c9eeaefdbd3fab582520c471c77'),])
 
# I = p*hash_to_point(str(P[l]))

# s,c1,D = generate_CLSAG(msg,p,P,z,C_offset,C,C_nonzero)
# import ipdb;ipdb.set_trace()
# check_CLSAG(msg, s, c1, D, I, P, C_nonzero, C_offset)



# tx_to_check = ['c39652b79beb888464525fee06c3d078463af5b76d493785f8903cae93405603']
# i_tx = 0
# settings.node_choice(1)

# resp_json,resp_hex = com_db.get_tx(tx_to_check,i_tx) 
# inputs = len(resp_json['vin'])
# outputs = len(resp_json['vout'])

# rows = len(resp_json['vin'][0]['key']['key_offsets'])
# msg = get_tx_hash_clsag(resp_json,resp_hex)
# pubs_aux = misc_func.get_members_in_ring(tx_to_check,i_tx,inputs,rows)
# masks_aux = misc_func.get_masks_in_ring(resp_json,inputs,rows)

# pubs = pubs_aux[0]
# masks = masks_aux[0] 

# sig_ind = 0
# C_offset = misc_func.get_pseudo_outs(resp_json,sig_ind) #C_offset
# ss = resp_json["rctsig_prunable"]["CLSAGs"][0]["s"]
# s_scalar = misc_func.s_to_scalar(ss,rows)
# c1 = Scalar(resp_json["rctsig_prunable"]["CLSAGs"][0]["c1"])
# D = Point(resp_json["rctsig_prunable"]["CLSAGs"][0]["D"])
# # PK = misc_func.point_matrix_mg(pubs[sig_ind],masks[sig_ind],pseudoOuts)
# I = Point(resp_json["vin"][sig_ind]["key"]["k_image"])

# # check_CLSAG(msg, s_scalar, I, c1, D, pubs, masks, C_offset)

# import ipdb;ipdb.set_trace()
# check_CLSAG(msg, s_scalar, c1, D, I, pubs, masks, C_offset)







