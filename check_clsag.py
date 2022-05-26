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
from dumber25519 import Scalar, Point, PointVector, ScalarVector,hash_to_point,hash_to_scalar
import copy
import multiprocessing
import check_rangeproofs
from concurrent.futures import as_completed, ProcessPoolExecutor






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

    strC = ''
    for i in range(len(C)):
        strC += str(C[i])

    strC_nonzero = ''
    for i in range(len(C_nonzero)):
        strC_nonzero += str(C_nonzero[i])

    # Now generate the signature
    mu_P = hash_to_scalar(str_agg0+strP+strC_nonzero+str(I)+str(D)+str(C_offset))
    mu_C = hash_to_scalar(str_agg1+strP+strC_nonzero+str(I)+str(D)+str(C_offset))
    s = [None]*n

    import ipdb;ipdb.set_trace()
    # alpha = random_scalar()
    alpha= Scalar('164935f9454e3915b324f2f7b922fb4f4e75031aa479586b1006801202842a0b')

    # Scalars are either random (seed is None) or hash-constructed
    # if seed is None:
        # s = [random_scalar() for _ in range(n)]
    # else:
        # s = [hash_to_scalar('CLSAG_scalar',seed,I,i) for i in range(n)]

    # Private index
    aG = dumber25519.G*alpha
    aH = hash_to_point(str(P[l]))*alpha
    c = hash_to_scalar(str_round+strP+strC_nonzero+str(C_offset)+str(msg)+str(aG)+str(aH))

    print('c: ')
    print(c)
   
    i = (l+1) % n
    if (i==0):
        c1 = copy.copy(c)

    s[2] = Scalar('b4ef81df870d75062d445f753d3464dc5827d367c9db019637b5f93d35cae802')
    s[3] = Scalar('e3034af765ee80f8cb7022c2507ba91a7d75c56adfaf0f4e519ffe88af1e7107')
    s[4] = Scalar('9bd82de4ee5c7e5665a71e090d58ea5b7e77e94e6876f66854f91d327737fa0d')
    s[5] = Scalar('1e03dfcdd0698f168dfe8724916dbf2a875de6390eeee7048734b7104aa68b04')
    s[6] = Scalar('3ea13d823dc970749ddc636fa286efb79fa8769901e474307797697ad0a22602')
    s[7] = Scalar('491d0e8a6b41241035abd072247580f69807c0ecf65e8c7a7d2728b110f0d90b')
    s[8] = Scalar('d542c8e33da51dd40de744b975c48b32935c618c70d22fbf4804811490553b0c')
    s[9] = Scalar('9b03cfa88bf24d2d239f99ba9dd87f1c4cc3d759e29c6e9329fa42c08bef400c')
    s[10] = Scalar('1e41e3e8286d0b1abe82e120fa8f7229b6726056726c429a5d0d33a51f508a06')
    s[0] = Scalar('0b3e2523e53e4998dc6743eae59eb6c427f6027f3b83ba21c9746c00ad4ec60c')


    while (i!=l):
        # s[i] = random_scalar()
        cp = c*mu_P
        cc = c*mu_C

        L = s[i]*dumber25519.G + cp*P[i]+ cc*C[i]

        R = s[i]*hash_to_point(str(P[i])) + cp*I + cc*D*Scalar(8)

        print('P: ')
        print(P[i])

        print('C: ')
        print(C[i])

        print('Hi :')
        print(hash_to_point(str(P[i])))

        print('R: ')
        print(R)

        print('L: ')
        print(L)
                    # str_round+strP+strC_nonzero+str(C_offset)+str(msg)
        str_hash = str_round+strP+strC_nonzero+str(C_offset)+str(msg)
        str_hash += str(L) + str(R)

        c = hash_to_scalar(str_hash)

        print('c: ')
        print(c)

        i = (i+1) % n
        if i==0:
            c1 = copy.copy(c)


    import ipdb;ipdb.set_trace()
    
    s[l] = alpha - c*(p*mu_P+mu_C*z)



        

    # Decoy indices
    # if n > 1:
        # for i in range(l+1,l+n):
            # i = i % n
            # L = G*s[i] + P[i]*(h[i]*mu_P) + C[i]*(h[i]*mu_C)
            # R = hash_to_point(P[i])*s[i] + I*(h[i]*mu_P) + D*(h[i]*mu_C)
            # h[(i+1) % n] = hash_to_scalar('CLSAG_round',P,C,M,L,R)

    # # Final scalar computation
    # s[l] = alpha - h[l]*(mu_P*p + mu_C*z)

    # # Assemble the signature
    # sig = Signature()
    # sig.h0 = h[0]
    # sig.s = s
    # sig.I = I
    # sig.D = D

    return s,I,D




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


msg = str('612ebe1b1bfdd4f49732afedc43f4c815f899e190f316eda75fad5423e53b8e6')
p = Scalar('073d1d6d6d3ec1b47b03b40d4fd9fec97fca4b61ed49a66bb32e818b5d9c710f')
z = Scalar('64aca5a5c70ff73ef3a192f8286efb1353eb8c642ef96d8c263d8b4ea2259b0c')
C_offset = Point('feae5544786270b394a8f34f753d550be92a318c291926b7d9bfa7fb4cde3745')
l = 1

P = PointVector([ Point('af837eefa0de5135777b7cc52f8a68d8a883b22f156bf0e04873548b9caa8edb'),Point('1e9e346d687fc94c102a0ee70d050ba70d8135a366581a98e2c45e8926e8ed83'),Point('267b7f48f760219278443f40d5edb097d82b1aa7e7e6a6cae084f19d18f7b3c7'),Point('88afa48a95ce58cdc9eb988abdc9c3b9226efe1ddd12b6ab0a4afec3be6faee7'),Point('9be7a0ea0cee158f788f0ab788e0ec3db67f2a288a8a64c0e1d85056d06ba908'),Point('82f204a77a869456afc5a345a1770dc1beed379b2bfb3c331294220d6d9ca0c6'),Point('99b32f89d6b860ad58109829b1eed052188a1d6a8ba1e965ae4b82fae7f02411'),Point('abddfd5f34fa96cfc93058feb189e6433cbdcdbfd9e13286d9109448c142e720'),Point('7f23a1a5680516f6f3056ffff709e1780d1e5fa826ebfd097b6f0fd98e758cc3'),Point('5ad9278b0be168f15b9fa5c68537c68f3f37f03d7999a1e6e8f4e28882dc4320'),Point('993f2ef0adc11ddd1f7414f5049cf94cb3742423b5309bc9944e0752fcdcf342'),])
 
C = PointVector([ Point('de50d6aabc7bd68eff67bded347d494140d8ed0c12a6785a0ba3dad497b24c86'),Point('a1ec7c218ae64b7e0dad3330ab1e1abd7902aca944992b4ba8caa9201682fa07'),Point('6ca7bd3e3863ea0a8710fe893b8a27f0f4c834d7a82699db1711eaacab079f24'),Point('2f07ff1641083850605c04059e17aad0241e10b65994f1ffcc34f3e2c80e716f'),Point('d4f2e9080afe0296164554e5846cea8955b489af4f8bb531a8e34a1f80e7a02b'),Point('1172a23df246f5973b12541d2068afa16159a1fdc421aab27fca6b9fab09bfab'),Point('88f1b21020e38d50c7fd98feefc6253291613db00129654d786320318a6880d4'),Point('8522ddaae47f142fa34654d828674b51357e74c75cbe55501b600806c5506576'),Point('faab64f49cac9dcf53cb0de21a41be20a3234369b1b5609305fa737f4a9413ce'),Point('e751f0ef44cdeb6d5e5821e8013e7de02e9522651b8b9763a304468979b86008'),Point('d6f3ab5d6f9bf2569c12f7fa800dbfe66a69e406db7e6318cfb26ab1e966d262'),])
 
C_nonzero = PointVector([ Point('ef056230343b70feb26fc4c3cde31c96ec6481f9815893240c72cf2e55a20678'),Point('0fcba4f8a5794d45c0bb0c9bae361857285a05a72704f0af27319dfbb02e5868'),Point('0b77f1a2395294b40cf5a3b1d7e1d9e3615e3262ca2e2cd5e8e4c975d01d4ff4'),Point('94fe96babf8986539db8ab69a219733c5280d5d2b5d7d64af70f04fb66eb402e'),Point('b308f21f6749df01857bd39829f1c84beed823a569577a78f447f1cbdd7f9852'),Point('b8178cc7aff509d42872eec29e0f089c2128f9a2e7fd3a0494e20cad6216cf47'),Point('d148d43672a326e22a2374d9c865cabfbeb555d7cb7e5eb9899c9c4fecb05936'),Point('cd478010293e2f298f3b21243e14fdb4f1806ae030b3c3a65585e60ad2c61a56'),Point('166d0ebf687ccb8a459c407261be109304eeef9f89e8cb6bd40b5f8515f9c128'),Point('eb90be4a8d3810d05113e2eec14bb7e0c3d244a974a1732e19c81716042a7984'),Point('43f3aaf9d2f142621661985916cd8d7e7e9c1c9eeaefdbd3fab582520c471c77'),])
 

import ipdb;ipdb.set_trace()
sig = generate_CLSAG(msg,p,P,z,C_offset,C,C_nonzero)


