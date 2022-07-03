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
from dumber25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point,cn_fast_hash
import copy
import varint_mic as varint
import multiprocessing

def check_sig_Borromean(resp_json,sig_ind):
    P1,P2,bbee,bbs0,bbs1 = get_borromean_vars(resp_json,sig_ind)
    verified, str_out = check_Borromean(P1,P2,bbee,bbs0,bbs1)
    if not verified:
        print('Potential inflation in Borromean Signatures! Please verify what is happening!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in Borromean ring signature! Please verify what is happening!') 
        raise Exception('borromean_signature_failure')
    return str_out

def check_commitments(resp_json):
    
    str_com = ''
    str_com += '\n--------------------------------------------------------\n'
    str_com += '------------------Checking Commitments------------------\n'
    str_com += '--------------------------------------------------------\n'
    if "pseudoOuts" in resp_json["rct_signatures"]:
        Cin = Scalar(0)*dumber25519.G
        Cout = Scalar(0)*dumber25519.G
        for i in range(len(resp_json["rct_signatures"]["pseudoOuts"])):
            Cin += Point(resp_json["rct_signatures"]["pseudoOuts"][i])
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            Cout += Point(resp_json["rct_signatures"]["outPk"][i])
        Fee = Scalar(resp_json["rct_signatures"]["txnFee"])*dumber25519.H

        str_com += 'Sum of Cin = ' +str(Cin)
        str_com += '\n'
        str_com += 'Sum of Cout = ' +str(Cout)
        str_com += '\n'
        str_com += 'Fee = ' +str(Fee)
        str_com += '\n'
        res = Cin - Cout - Fee
        str_com += 'Result (Cin - Cout - Fee) = ' +str(res)
        str_com += '\n'
        if res != dumber25519.Z:
            str_com += 'Inflation may be happening! Commitments do not match!'
            print('Inflation may be happening! Commitments do not match!')
            with open("error.txt", "a+") as file1:
                # Writing data to a file
                file1.write(str(resp_json))
                file1.write('\nPotential inflation in checking commitments! Please verify what is happening!') 
            raise Exception('commitments_failure')
        else:
            str_com += 'Commitments match. No inflation is happening.'
            
    else:
        str_com += 'Commitments must match in RCTTypeFull transactions. Otherwise the MLSAG ring signature would fail.'

    str_com += '\n'
    str_com += '--------------------------------------------------------'
    str_com += '\n'
    return str_com
        







def get_borromean_vars(resp_json,ind):
    Ci = resp_json["rctsig_prunable"]["rangeSigs"][ind]["Ci"]
    asig = resp_json["rctsig_prunable"]["rangeSigs"][ind]["asig"]
    P1,P2,bbee,bbs0,bbs1 = [],[],[],[],[]
    factors = len(asig)//64 - 1 #=128
    bbee = Scalar(asig[-64:])
    for i in range(factors//2):
        bbs0.append(Scalar(asig[64*i:64*(i+1)]))
        bbs1.append(Scalar(asig[64*64+64*i:64*64+64*(i+1)]))
        P1.append(Point(Ci[64*i:64*(i+1)]))
        P2.append(P1[i]-Scalar(2**i * 8)*dumber25519.Point(dumber25519.cn_fast_hash(str(dumber25519.G))))

    return P1,P2,bbee,bbs0,bbs1


def check_Borromean(P1,P2,bbee,bbs0,bbs1,details=0):
    # t1 = time.time()
    LV = ''
    str_out = '\n'
    str_out += '--------------------------------------------------------\n'
    str_out += '-----------Checking Borromean Ring Signature------------\n'
    str_out += '--------------------------------------------------------'
    str_out += '\n'
    for j in range(64):
        LL = bbee*P1[j] + bbs0[j]*dumber25519.G
        chash = dumber25519.hash_to_scalar(str(LL))
        LV += str(chash*P2[j] + bbs1[j]*dumber25519.G) 
        str_out += str('LL = ')
        str_out += str(LL)
        str_out += '\n'

    eeComp = dumber25519.hash_to_scalar(LV)
    str_out += str('eeComp = ')
    str_out += str(eeComp)
    str_out += '\n'
    # print('Time to check Borromean:', (time.time()-t1))
    res = (bbee - eeComp) 
    str_out += '\n'
    str_out += str('Result: ')
    str_out += '\n'
    str_out += str(res) 
    str_out += '\n'
    if res == Scalar(0):
        str_out += 'Borromean verification done. Everything is fine.'
    else:
        str_out += 'Borromean verification failed! There may be some inflation happening!'
    str_out += '\n'
    str_out += '--------------------------------------------------------'
    str_out += '\n'

    return res == Scalar(0), str_out

def generate_Borromean(ai,Ci,CiH,b):
    alpha = []
    bbs1 = misc_func.scalar_matrix(64,0,0) 
    bbs0 = misc_func.scalar_matrix(64,0,0) 
    L1 = ''
    L = misc_func.point_matrix(2,64,0)
    for i in range(64):
        naught = int(b[i])
        prime = (int(b[i])+1)%2
        alpha.append(dumber25519.random_scalar())
        L[naught][i] = alpha[i]*dumber25519.G
        if naught == 0:
            bbs1[i] = dumber25519.random_scalar()
            c = dumber25519.hash_to_scalar(str(L[naught][i]))
            L[prime][i] = bbs1[i]*dumber25519.G + c*CiH[i]
        L1 += str(L[1][i])

    bbee = dumber25519.hash_to_scalar(L1)

    for j in range(64):
        if  int(b[j])==0:
            bbs0[j] = alpha[j]-ai[j]*bbee
        else:
            bbs0[j] = dumber25519.random_scalar()
            LL=bbs0[j]*dumber25519.G+bbee*Ci[j]
            cc = dumber25519.hash_to_scalar(str(LL))
            bbs1[j] = alpha[j]-ai[j]*cc

    return bbee,bbs0,bbs1 





########################## Bulletproofs ###########################

def check_commitments_bp1(resp_json):
    
    str_com = ''
    str_com += '\n--------------------------------------------------------\n'
    str_com += '------------------Checking Commitments------------------\n'
    str_com += '--------------------------------------------------------\n'
    Cin = Scalar(0)*dumber25519.G
    Cout = Scalar(0)*dumber25519.G
    for i in range(len(resp_json["rctsig_prunable"]["pseudoOuts"])):
        Cin += Point(resp_json["rctsig_prunable"]["pseudoOuts"][i])
    for i in range(len(resp_json["rct_signatures"]["outPk"])):
        Cout += Point(resp_json["rct_signatures"]["outPk"][i])
    Fee = Scalar(resp_json["rct_signatures"]["txnFee"])*dumber25519.H

    str_com += 'Sum of Cin = ' +str(Cin)
    str_com += '\n'
    str_com += 'Sum of Cout = ' +str(Cout)
    str_com += '\n'
    str_com += 'Fee = ' +str(Fee)
    str_com += '\n'
    res = Cin - Cout - Fee
    str_com += 'Result (Cin - Cout - Fee) = ' +str(res)
    str_com += '\n'
    if res != dumber25519.Z:
        str_com += 'Inflation may be happening! Commitments do not match!'
        print('Inflation may be happening! Commitments do not match!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in checking commitments! Please verify what is happening!') 
        raise Exception('commitments_failure')
            
    str_com += '\n'
    str_com += '--------------------------------------------------------'
    str_com += '\n'
    return str_com


def check_sig_bp1(resp_json):
    # P1,P2,bbee,bbs0,bbs1 = get_borromean_vars(resp_json,sig_ind)
    proofs = get_vars_bp1(resp_json)
    # verified, str_out = check_Borromean(P1,P2,bbee,bbs0,bbs1)
    verified, str_out = check_bp1([proofs])
    if not verified:
        print('Potential inflation in Bulletproofs1 Signatures! Please verify what is happening!')
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write('\nPotential inflation in Bulletproofs1 ! Please verify what is happening!') 
        raise Exception('bulletproof1_failed')
    return str_out


def get_vars_bp1(resp_json):
    inv8 = Scalar(8).invert()
    ind = 0
    N = 64
    A = Point(resp_json["rctsig_prunable"]["bp"][ind]["A"])
    S = Point(resp_json["rctsig_prunable"]["bp"][ind]["S"])
    T1 = Point(resp_json["rctsig_prunable"]["bp"][ind]["T1"])
    T2 = Point(resp_json["rctsig_prunable"]["bp"][ind]["T2"])
    taux = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["taux"])
    mu = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["mu"])
    L_aux = resp_json["rctsig_prunable"]["bp"][ind]["L"]
    R_aux = resp_json["rctsig_prunable"]["bp"][ind]["R"]

    L = PointVector()
    for i in range(len(L_aux)):
        L.append(Point(L_aux[i]))

    R = PointVector()
    for i in range(len(R_aux)):
        R.append(Point(R_aux[i]))

    a = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["a"])
    b = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["b"])
    t = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["t"])

    outPk_aux = resp_json["rct_signatures"]["outPk"]
    V = PointVector()
    for i in range(len(outPk_aux)):
        V.append(inv8*Point(outPk_aux[i]))

    return [V,A,S,T1,T2,taux,mu,L,R,a,b,t]


# Verify a batch of multi-output proofs
# proofs: list of proof data lists
# N: number of bits in range
def check_bp1(proofs):
    N = 64
    # determine the length of the longest proof
    max_MN = 2**max([len(proof[7]) for proof in proofs])
    # print('max_MN: ',max_MN)

    # curve points
    Z = dumber25519.Z
    G = dumber25519.G

    domain = str("bulletproof")
    # H = hash_to_point(cn_fast_hash(strH.encode('utf-8').hex()))
    H = Scalar(8) * Point(cn_fast_hash(str(G)))
    Hi = PointVector([hash_to_point(cn_fast_hash(str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*max_MN,2)])
    Gi = PointVector([hash_to_point(cn_fast_hash(str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*max_MN+1,2)])

    # set up weighted aggregates
    y0 = Scalar(0)
    y1 = Scalar(0)
    z1 = Scalar(0)
    z3 = Scalar(0)
    z4 = [Scalar(0)]*max_MN
    z5 = [Scalar(0)]*max_MN
    scalars = ScalarVector([]) # for final check
    points = PointVector([]) # for final check

    # run through each proof
    for proof in proofs:

        V,A,S,T1,T2,taux,mu,L,R,a,b,t = proof
        # import ipdb;ipdb.set_trace()

        # get size information
        M = 2**len(L)//N

        # weighting factors for batching
        weight_y = random_scalar()
        weight_z = random_scalar()

        # weight_y = Scalar('269b29e4a54ed754b173165497adbb657f2833d08d4d61eaf55d1ec8ac91c706')
        # weight_z = Scalar('c7297e7085a86731dda22d5e9e761b1e4e5a97115e4379be721e1f7a8fea470e')


        if weight_y == Scalar(0) or weight_z == Scalar(0):
            raise ArithmeticError


        strV = ''
        for i in range(len(V)):
            strV = strV+str(V[i])
        hash_cache = str(hash_to_scalar(strV))

        # reconstruct all challenges
        y = mash(str(hash_cache),str(A),str(S)) 
        hash_cache = copy.copy(y)

        if y == Scalar(0):
            raise ArithmeticError
        y_inv = y.invert()

        if y == Scalar(0):
            raise ArithmeticError

        z = hash_to_scalar(str(y))
        hash_cache = copy.copy(z)

        x = mash(str(hash_cache),str(z),str(T1),str(T2))

        hash_cache = copy.copy(x)

        if x == Scalar(0):
            raise ArithmeticError

        x_ip = mash(str(hash_cache),str(x),str(taux),str(mu),str(t))
        hash_cache = copy.copy(x_ip)

        if x_ip == Scalar(0):
            raise ArithmeticError

        y0 += -taux*weight_y
        
        ip1y = sum_scalar(y,M*N)
        k = -(z**2)*ip1y
        # k = (z-z**2)*sum_scalar(y,M*N)
        for j in range(1,int(M+1)):
            k -= (z**(j+2))*sum_scalar(Scalar(2),N)

        y1 = (t-(z*ip1y+k))*weight_y


        for j in range(len(V)):
            scalars.append(z**(j+2)*weight_y)
            points.append(V[j]*Scalar(8))
        scalars.append(x*weight_y)
        points.append(T1*Scalar(8))
        scalars.append(x**2*weight_y)
        points.append(T2*Scalar(8))

        scalars.append(weight_z)
        points.append(A*Scalar(8))
        scalars.append(x*weight_z)
        points.append(S*Scalar(8))

        # inner product
        W = ScalarVector([])
        for i in range(len(L)):
            W.append(mash(str(hash_cache),str(L[i]),str(R[i])))
            hash_cache = copy.copy(W[i])
            if W[i] == Scalar(0):
                raise ArithmeticError
        W_inv = W.invert()


        for i in range(M*N):
            index = copy.copy(i)
            g = copy.copy(a)
            h = b*((y_inv)**i)
            for j in range(len(L)-1,-1,-1):
                J = len(W)-j-1
                base_power = 2**j
                if index//base_power == 0:
                    g *= W_inv[J]
                    h *= W[J]
                else:
                    g *= W[J]
                    h *= W_inv[J]
                    index -= base_power

            g += z
            h -= (z*(y**i) + (z**(2+i//N))*(Scalar(2)**(i%N)))*((y_inv)**i)

            z4[i] = -g*weight_z
            z5[i] = -h*weight_z

        z1 += mu*weight_z

        for i in range(len(L)):
            scalars.append(W[i]**2*weight_z)
            points.append(L[i]*Scalar(8))
            scalars.append(W_inv[i]**2*weight_z)
            points.append(R[i]*Scalar(8))
        z3 += (t-a*b)*x_ip*weight_z

    # now check all proofs together
    scalars.append(y0-z1)
    points.append(G)
    scalars.append(z3-y1)
    points.append(H)
    # import ipdb;ipdb.set_trace()
    for i in range(M*N):
        scalars.append(z4[i])
        points.append(Gi[i])
        scalars.append(z5[i])
        points.append(Hi[i])
    
    str_out = ''
    str_out += '\n--------------------------------------------------------\n'
    str_out += '------------------Checking Rangeproofs------------------\n'
    str_out += '--------------------------------------------------------\n'
    str_out += 'Verifying the Bulletproofs equation with inputs: \n'
    str_out += '\nV: \n'
    str_out += str(V)
    str_out += '\nA: \n'
    str_out += str(A)
    str_out += '\nS: \n'
    str_out += str(S)
    str_out += '\nT1: \n'
    str_out += str(T1)
    str_out += '\nT2: \n'
    str_out += str(T2)
    str_out += '\ntaux: \n'
    str_out += str(taux)
    str_out += '\nmu: \n'
    str_out += str(mu)
    str_out += '\nL: \n'
    str_out += str(L)
    str_out += '\nR: \n'
    str_out += str(R)
    str_out += '\na: \n'
    str_out += str(a)
    str_out += '\nb: \n'
    str_out += str(b)
    str_out += '\nt: \n'
    str_out += str(t)
    
    str_out += '\n'
    # res = dumber25519.multiexp(scalars,points)
    # import ipdb;ipdb.set_trace()
    if not dumber25519.multiexp(scalars,points) == Z:
        raise ArithmeticError('Bad z check!')
        str_out += 'Bulletproof check FAILED'
        return False, str_out

    
    str_out += 'Bulletproof passed!'
    str_out += 'The value commited represents the true value with a negligible probability otherwise.'
    return True, str_out



################### BP functions ##################


def mash(hcache,s1,s2='',s3='',s4=''):
    cache = hash_to_scalar(str(hcache)+str(s1)+str(s2)+str(s3)+str(s4))
    return cache

# Clear the transcript hash
def clear_cache():
    global cache
    cache = ''

# Turn a scalar into a vector of bit scalars
# s: Scalar
# N: int; number of bits
#
# returns: ScalarVector
def scalar_to_bits(s,N):
    result = []
    for i in range(N-1,-1,-1):
        if s/Scalar(2**i) == Scalar(0):
            result.append(Scalar(0))
        else:
            result.append(Scalar(1))
            s -= Scalar(2**i)
    return ScalarVector(list(reversed(result)))

# Generate a vector of powers of a scalar
# s: Scalar
# l: int; number of powers to include
#
# returns: ScalarVector
def exp_scalar(s,l):
    return ScalarVector([s**i for i in range(l)])

# Sum the powers of a scalar
# s: Scalar
# l: int; number of powers to include
#
# returns: Scalar; s^0+s^1+...+s^(l-1)
def sum_scalar(s,l):
    if not int(l) & int(l-1) == 0:
        raise ValueError('We need l to be a power of 2!')

    if l == 0:
        return Scalar(0)
    if l == 1:
        return Scalar(1)

    r = Scalar(1) + s
    while l > 2:
        s = s*s
        r += s*r
        l = l // 2
    return r

# Perform an inner-product proof round
# G,H: PointVector
# U: Point
# a,b: ScalarVector
#
# returns: G',H',U,a',b',L,R
def inner_product(data,hash_cache):
    G,H,U,a,b,L,R = data

    n = len(G)
    if n == 1:
        return [a[0],b[0]],hash_cache

    n = n // 2
    cL = a[:n]**b[n:]
    cR = a[n:]**b[:n]
    L = (G[n:]*a[:n] + H[:n]*b[n:] + U*cL)*inv8
    R = (G[:n]*a[n:] + H[n:]*b[:n] + U*cR)*inv8

    x = mash(str(hash_cache),str(L),str(R)) #corresponds to w[round]
    hash_cache = copy.copy(x)
    print('cL: ')
    print(cL)
    print('cR: ')
    print(cR)
    print('x: ')
    print(x)
    # x = copy.copy(cache)

    G = (G[:n]*x.invert())*(G[n:]*x)
    H = (H[:n]*x)*(H[n:]*x.invert())

    a = a[:n]*x + a[n:]*x.invert()
    b = b[:n]*x.invert() + b[n:]*x
    
    return [G,H,U,a,b,L,R] ,hash_cache
