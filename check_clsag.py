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


def check_CLSAG(msg, s, c1, D_aux,I, P, C_nonzero, C_offset):
    
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

    print('c: ')
    print(c)

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

        print('c: ')
        print(c)

    c_final = c - c1

    import ipdb;ipdb.set_trace()

    return c_final




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



msg = str('612ebe1b1bfdd4f49732afedc43f4c815f899e190f316eda75fad5423e53b8e6')
p = Scalar('073d1d6d6d3ec1b47b03b40d4fd9fec97fca4b61ed49a66bb32e818b5d9c710f')
z = Scalar('64aca5a5c70ff73ef3a192f8286efb1353eb8c642ef96d8c263d8b4ea2259b0c')
C_offset = Point('feae5544786270b394a8f34f753d550be92a318c291926b7d9bfa7fb4cde3745')
l = 1

P = PointVector([ Point('af837eefa0de5135777b7cc52f8a68d8a883b22f156bf0e04873548b9caa8edb'),Point('1e9e346d687fc94c102a0ee70d050ba70d8135a366581a98e2c45e8926e8ed83'),Point('267b7f48f760219278443f40d5edb097d82b1aa7e7e6a6cae084f19d18f7b3c7'),Point('88afa48a95ce58cdc9eb988abdc9c3b9226efe1ddd12b6ab0a4afec3be6faee7'),Point('9be7a0ea0cee158f788f0ab788e0ec3db67f2a288a8a64c0e1d85056d06ba908'),Point('82f204a77a869456afc5a345a1770dc1beed379b2bfb3c331294220d6d9ca0c6'),Point('99b32f89d6b860ad58109829b1eed052188a1d6a8ba1e965ae4b82fae7f02411'),Point('abddfd5f34fa96cfc93058feb189e6433cbdcdbfd9e13286d9109448c142e720'),Point('7f23a1a5680516f6f3056ffff709e1780d1e5fa826ebfd097b6f0fd98e758cc3'),Point('5ad9278b0be168f15b9fa5c68537c68f3f37f03d7999a1e6e8f4e28882dc4320'),Point('993f2ef0adc11ddd1f7414f5049cf94cb3742423b5309bc9944e0752fcdcf342'),])
 
C = PointVector([ Point('de50d6aabc7bd68eff67bded347d494140d8ed0c12a6785a0ba3dad497b24c86'),Point('a1ec7c218ae64b7e0dad3330ab1e1abd7902aca944992b4ba8caa9201682fa07'),Point('6ca7bd3e3863ea0a8710fe893b8a27f0f4c834d7a82699db1711eaacab079f24'),Point('2f07ff1641083850605c04059e17aad0241e10b65994f1ffcc34f3e2c80e716f'),Point('d4f2e9080afe0296164554e5846cea8955b489af4f8bb531a8e34a1f80e7a02b'),Point('1172a23df246f5973b12541d2068afa16159a1fdc421aab27fca6b9fab09bfab'),Point('88f1b21020e38d50c7fd98feefc6253291613db00129654d786320318a6880d4'),Point('8522ddaae47f142fa34654d828674b51357e74c75cbe55501b600806c5506576'),Point('faab64f49cac9dcf53cb0de21a41be20a3234369b1b5609305fa737f4a9413ce'),Point('e751f0ef44cdeb6d5e5821e8013e7de02e9522651b8b9763a304468979b86008'),Point('d6f3ab5d6f9bf2569c12f7fa800dbfe66a69e406db7e6318cfb26ab1e966d262'),])
 
C_nonzero = PointVector([ Point('ef056230343b70feb26fc4c3cde31c96ec6481f9815893240c72cf2e55a20678'),Point('0fcba4f8a5794d45c0bb0c9bae361857285a05a72704f0af27319dfbb02e5868'),Point('0b77f1a2395294b40cf5a3b1d7e1d9e3615e3262ca2e2cd5e8e4c975d01d4ff4'),Point('94fe96babf8986539db8ab69a219733c5280d5d2b5d7d64af70f04fb66eb402e'),Point('b308f21f6749df01857bd39829f1c84beed823a569577a78f447f1cbdd7f9852'),Point('b8178cc7aff509d42872eec29e0f089c2128f9a2e7fd3a0494e20cad6216cf47'),Point('d148d43672a326e22a2374d9c865cabfbeb555d7cb7e5eb9899c9c4fecb05936'),Point('cd478010293e2f298f3b21243e14fdb4f1806ae030b3c3a65585e60ad2c61a56'),Point('166d0ebf687ccb8a459c407261be109304eeef9f89e8cb6bd40b5f8515f9c128'),Point('eb90be4a8d3810d05113e2eec14bb7e0c3d244a974a1732e19c81716042a7984'),Point('43f3aaf9d2f142621661985916cd8d7e7e9c1c9eeaefdbd3fab582520c471c77'),])
 
I = p*hash_to_point(str(P[l]))

s,c1,D = generate_CLSAG(msg,p,P,z,C_offset,C,C_nonzero)
import ipdb;ipdb.set_trace()
check_CLSAG(msg, s, c1, D, I, P, C_nonzero, C_offset)



tx_to_check = ['c39652b79beb888464525fee06c3d078463af5b76d493785f8903cae93405603']
i_tx = 0
settings.node_choice(1)

resp_json,resp_hex = com_db.get_tx(tx_to_check,i_tx) 
inputs = len(resp_json['vin'])
outputs = len(resp_json['vout'])

rows = len(resp_json['vin'][0]['key']['key_offsets'])
msg = get_tx_hash_clsag(resp_json,resp_hex)
pubs_aux = misc_func.get_members_in_ring(tx_to_check,i_tx,inputs,rows)
masks_aux = misc_func.get_masks_in_ring(resp_json,inputs,rows)

pubs = pubs_aux[0]
masks = masks_aux[0] 

sig_ind = 0
C_offset = misc_func.get_pseudo_outs(resp_json,sig_ind) #C_offset
ss = resp_json["rctsig_prunable"]["CLSAGs"][0]["s"]
s_scalar = misc_func.s_to_scalar(ss,rows)
c1 = Scalar(resp_json["rctsig_prunable"]["CLSAGs"][0]["c1"])
D = Point(resp_json["rctsig_prunable"]["CLSAGs"][0]["D"])
# PK = misc_func.point_matrix_mg(pubs[sig_ind],masks[sig_ind],pseudoOuts)
I = Point(resp_json["vin"][sig_ind]["key"]["k_image"])

# check_CLSAG(msg, s_scalar, I, c1, D, pubs, masks, C_offset)

import ipdb;ipdb.set_trace()
check_CLSAG(msg, s_scalar, c1, D, I, pubs, masks, C_offset)




# msg = str('0192b64f0541c5c1e91eb1740268b5cb4ca22f37257b7722dd45701332a872d8')
# C_offset = Point('12ce06159712f9c3c61b400ab11dbb6da7d147020e1ba5135bcacb93948d35d3')
# c1 = Scalar('7f4d67bdba16fee1012e3dfbb1760828ea5b40ed4baffb34ecf0c57a8daf5002')
# D = Point('1eca0d6dc70eced9fee152a618b9fce6e44f392d312eb6cfc7f63fc5d8b8b75f')
# I = Point('f6dbf4e2a80234679156ee291f3167398d38659ee0301e0a4702f1f6de8d57a8')
# pubs = PointVector([ Point('0e87fdc5aaf234b06ce27df56820bc4d352094f133d1be2103ebc85957c23181'),Point('f2ca063c3ea5158768a50b2dd2be7e7c63b4fc9b5129425d090d9c8e3996a981'),Point('e10debc98fa068ed75d814e42a72d2ea741a4415542bdab4d0505d9023ffae8e'),Point('e9a72d4371eee456d348997cc0e2448e40bafefea867fb4759be2739e12b6539'),Point('b2624fb64d96daea36003195cbf5e72303da96a783eb295b2508bafc75d1efb9'),Point('fc6ba92fc97235e05c1d9ee3854e7b0573adae020ee1f17e1873d95553364b4f'),Point('b818bcd216c0e8265abcc5ba28097b2a9241aae108dae0efe072c2fa54f26505'),Point('2c4d218545587eb91103013b004e393774246fafc96e5a00af732797f7712960'),Point('a7ac57d0206de53d1f5c1198fcc51e73e01533bdac028ac77fd1ce6ebd6df905'),Point('22780c26242c17808b20ed908b2b44a4bac82c4fafb989866c6037eb14fc30cb'),Point('68772cbe43a16f393b6a73f5967ccb4fbb3bac4a68b837c0a388a73393229c40'),])
 
# masks = PointVector([ Point('1c0b54de0806997120cf1f91a322ec71bd1c44be16229d5084cf71df59df2302'),Point('9f947905521d03ffc4a780fda265de395a8d90269506ae7387c1a625f596b704'),Point('7536f19a46e201e39210ed1011c4c920ea5c3fb380a75ece774c8eefbb5db358'),Point('f32088ee5389fad652c57ce0c4b9882335572cf8e3f4b4c3a0ab49bbcefb0e2c'),Point('c2a4cd3bd86ae7fa0343a3d6fead9c40d98e973c928bf25c4b368772838b2f81'),Point('ce817fdd48cfd3c96d9c01fb854e2544591cbdbff0a1a903d99eb660ceb9bb90'),Point('c6cc795b45b0fc76730cf213ee34b0a4fd413d93216f612a3044bf28221cfb56'),Point('8aa3f384a082e85cb7f62d34500f9d35e5506217fef176f0f2bc4d98d13ccae9'),Point('c97c77202a47e3d022e54fb9f29f5b2b894a3637afc725575d838239c3261beb'),Point('48886bad3b8e6ceb390173c2576257fa5692b566aee1812908d07fd0f7846612'),Point('afe5d170a9add73e11f9bbeaf677cae8cd327c415d59a043825929fcf1baee40'),])
 
# n = 11
# s = [None]*n
# s[0] = Scalar('1d68b17ab9bfe8a3222bfa83b02018bcd264bf2fc97194ba41025c1c74f7190a')
# s[1] = Scalar('888399bff66efc1c47b5d75383d4a790c2bb1e31edcae60eaa81f18a3f3bf905')
# s[2] = Scalar('6e897cf6b50c7755f41d064079e07ccd112eb938bebe1d42931dfe77e36e890f')
# s[3] = Scalar('b687f9ac9d1f9da8567bfaaf116b42f21996a5523c61dfb1bbdaa8b23e904a09')
# s[4] = Scalar('940349dea9754429399f9d87cf18ca28261485744fb0521ecab9a0e0011e110a')
# s[5] = Scalar('3e16f8228a011d570a46acf4fa9817d8d44441cf39a127a100dc1c5d14383e08')
# s[6] = Scalar('afbe5b4a55d34a81a78a935e750acca22cb754cedea81068819c1cdafe08930e')
# s[7] = Scalar('f4917f85a59136c3b4e69e149fd8e6c0d06842b3459f6ee7cd41e674429cf10f')
# s[8] = Scalar('00d1f52a87fc1acd7ed416630f15ea8fdfb0b1e320e12dc32c8a950384d03a0a')
# s[9] = Scalar('b787d3ef045e282d3011a26c7a4ea8e02b22fd96fbd4b9e4c01337850dcf6206')
# s[10] = Scalar('fa5cb10a9e9aca3047f668155a5628a57ab9b1570dc501952c4c645960e5f402')

# s_scalar = copy.copy(s)




