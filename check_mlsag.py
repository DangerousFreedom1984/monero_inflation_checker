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
import multiprocessing
import check_rangeproofs


def ring_sig_correct(h,resp_json,resp_hex,txs,i_tx,inputs,outputs,details):

        rows = len(resp_json['vin'][0]['key']['key_offsets'])
        message = get_tx_hash_mlsag(resp_json,resp_hex)
        pubs = misc_func.get_members_in_ring(txs,i_tx,inputs,rows)
        masks = misc_func.get_masks_in_ring(resp_json,inputs,rows)
        # import ipdb;ipdb.set_trace()

### Signature index
        # time_ver = time.time()
        for sig_ind in range(inputs):
            # import ipdb;ipdb.set_trace()
            try:
                y = multiprocessing.Process(target=check_sig_mlsag, args=(resp_json,sig_ind,inputs,rows,pubs,masks,message,details ))
                y.start()
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx]) + ' ring signature failed')

        for sig_ind in range(outputs):
            # import ipdb;ipdb.set_trace()
            try:
                x = multiprocessing.Process(target=check_rangeproofs.check_sig_Borromean, args=(resp_json,sig_ind, ))
                x.start()
            except:
                print('Verify block_height: '+str(h)+' tx : '+str(txs[i_tx])+' Borromean failed')
        # print('Total time verification', time.time() - time_ver)
        # print('Total time verification tx', time.time() - time_tx)


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
    else:
        if details==1:
            print(str_out)

    return 0

def generate_MLSAG(m,PK,sk,index):
    rows = len(PK)
    cols = len(PK[0])
    # I should check some stuff here like dimensions
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

    # import ipdb;ipdb.set_trace()
    c_old = dumber25519.hash_to_scalar(msg0)
    i = (index + 1) % rows
    if i==0:
        cc = copy.copy(c_old)
    
    ss = misc_func.scalar_matrix(rows,cols,0) 

    while (i!=index):
        # print('i: ',i)
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
        # print(c_old)
        i = (i+1)%rows
        if i==0:
            cc = copy.copy(c_old)

    # import ipdb;ipdb.set_trace()
    ss[index][0] = alpha0 - c_old*sk[0]
    ss[index][1] = alpha1 - c_old*sk[1] 

    return ss, cc, I0


def check_MLSAG(m,PK, I, c, ss,details=0):
    rows = len(PK)
    cols = len(PK[0])
    c_old = copy.copy(c)

    str_out = '\n'
    str_out += '--------------------------------------------------------'
    str_out += '\n'
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

    # I should check some stuff here like dimensions
    i = 0
    msg = ''
    msg += str(m)
    # import ipdb;ipdb.set_trace()
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

    
    str_out += 'Calculating c_old - c ' 
    str_out += '\n'
    res = (c_old-c) == Scalar(0)
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
    ph1 = resp_hex.split(extra_hex)[0] + extra_hex
    asig = resp_json["rctsig_prunable"]["rangeSigs"][0]["asig"]
    ph2 = resp_hex.split(extra_hex)[1].split(asig)[0]
    ph3 = resp_hex.split(resp_json["rct_signatures"]["outPk"][-1])[1].split(ss[0][0])[0]

    ph1_hash = dumber25519.cn_fast_hash(ph1)
    ph2_hash = dumber25519.cn_fast_hash(ph2)
    ph3_hash = dumber25519.cn_fast_hash(ph3)

    return dumber25519.cn_fast_hash(ph1_hash + ph2_hash + ph3_hash)

# message = '06bc62dbfc5a9b2d408a6a68a8d3d949fd0732f8a08067faef29e58b41c73c78'
# PK = [[Point('a9a0a41d7241649cf4f77f953287680f90a30c8878d49362b91cafd398be817c'),Point('ff4db1aee8d53b5d477ea200f20b4e4cb3615c3d8daf1cd45fe6e0d97bdd3316'),],[Point('0ada433a024c1cb115c70064b9e8e9379389c87759ab960754774689a0415721'),Point('3b7193bcb749c4bd0a5470309af38d88fee121a705a59232a6ff2f55ae5a1533'),],[Point('9855e371c4baa11f96f8afdbcf001e344a4f8ed20723a92b8bc13498d03f0750'),Point('aa12b65f356cd53f27ffcb0928846dcf43d095a346dda9e456289eac16f46e2e'),],[Point('59d87e0e3460085ce87e49322f3150dd1f8c085ee9a5b045d97179383dfe3937'),Point('3e3155e3bd7cb14a8c3dd820785ad1f32c810e078727a466bc236ffc5f7c2176'),],[Point('a91516d1fdb30eb9b37a61dba36e77caead71e276697b941d1fd84d0f25f7f6c'),Point('dfeb624430f3e81a4b7112043b8535a9b9c9193b0942f4103355500cb4f30880'),]]
# sk = [Scalar('ce3c86ee5e0174ff4314975ab48be6298801a7bfdb230de767d1847f6663fa05'),Scalar('1d4db898a3ece8d3a4982ca58b6c4deac8a54a72193570906f97d93db4d90108'),]
# index = 3


# ss, cc, I = generate_MLSAG(message,PK,sk,index)

# check_MLSAG(message,PK, I, cc, ss)
