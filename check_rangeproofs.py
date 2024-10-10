"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import json

# from varint import encode as to_varint
import df25519
from df25519 import (
    Scalar,
    Point,
    ScalarVector,
    PointVector,
    random_scalar,
    random_point,
    hash_to_scalar,
    hash_to_point,
    cn_fast_hash,
)
import copy
import varint_mic as varint
import multiprocessing
import settings_df25519
import time


#--------------------------------------------------------------------------------------------
### Commitments 
#--------------------------------------------------------------------------------------------
def check_commitments(resp_json):
    if "pseudoOuts" in resp_json["rct_signatures"]:
        Cin = Scalar(0) * df25519.G
        Cout = Scalar(0) * df25519.G
        for pseudoOut in resp_json["rct_signatures"]["pseudoOuts"]:
            Cin += Point(pseudoOut)
        for outPk in resp_json["rct_signatures"]["outPk"]:
            Cout += Point(outPk)
        Fee = Scalar(resp_json["rct_signatures"]["txnFee"]) * df25519.H
        res = Cin - Cout - Fee
        if res != df25519.Z:
            return False
        else:
            return True

    else:
        # "Commitments must match in RCTTypeFull transactions. Otherwise the MLSAG ring signature would fail."
        return True
#--------------------------------------------------------------------------------------------
def check_commitments_bp1(resp_json):
    Cin = df25519.Z
    Cout = df25519.Z
    for pseudoOut in resp_json["rctsig_prunable"]["pseudoOuts"]:
        Cin += Point(pseudoOut)
    for outPk in resp_json["rct_signatures"]["outPk"]:
        Cout += Point(outPk)
    Fee = Scalar(resp_json["rct_signatures"]["txnFee"]) * df25519.H

    res = Cin - Cout - Fee
    if res != df25519.Z:
        return False
    else:
        return True
#--------------------------------------------------------------------------------------------
### Borromean 
#--------------------------------------------------------------------------------------------
def check_sig_Borromean(resp_json, sig_ind):
    P1, P2, bbee, bbs0, bbs1 = get_borromean_vars(resp_json, sig_ind)
    return check_Borromean(P1, P2, bbee, bbs0, bbs1)
#--------------------------------------------------------------------------------------------
def get_borromean_vars(resp_json, ind):
    Ci = resp_json["rctsig_prunable"]["rangeSigs"][ind]["Ci"]
    asig = resp_json["rctsig_prunable"]["rangeSigs"][ind]["asig"]
    P1, P2, bbee, bbs0, bbs1 = [], [], [], [], []
    factors = len(asig) // 64 - 1  # =128
    bbee = Scalar(asig[-64:])
    for i in range(factors // 2):
        bbs0.append(Scalar(asig[64 * i : 64 * (i + 1)]))
        bbs1.append(Scalar(asig[64 * 64 + 64 * i : 64 * 64 + 64 * (i + 1)]))
        P1.append(Point(Ci[64 * i : 64 * (i + 1)]))
        P2.append(
            P1[i]
            - Scalar(2**i * 8)
            * df25519.Point(df25519.cn_fast_hash(str(df25519.G)))
        )

    return P1, P2, bbee, bbs0, bbs1
#--------------------------------------------------------------------------------------------
def check_Borromean(P1, P2, bbee, bbs0, bbs1, details=0):
    LV = ""
    for j in range(64):
        LL = bbee * P1[j] + bbs0[j] * df25519.G
        chash = df25519.hash_to_scalar(str(LL))
        LV += str(chash * P2[j] + bbs1[j] * df25519.G)

    eeComp = df25519.hash_to_scalar(LV)
    res = bbee - eeComp
    return res == Scalar(0) 
#--------------------------------------------------------------------------------------------
def generate_Borromean(ai, Ci, CiH, b):
    alpha = []
    bbs1 = misc_func.scalar_matrix(64, 0, 0)
    bbs0 = misc_func.scalar_matrix(64, 0, 0)
    L1 = ""
    L = misc_func.point_matrix(2, 64, 0)
    for i in range(64):
        naught = int(b[i])
        prime = (int(b[i]) + 1) % 2
        alpha.append(df25519.random_scalar())
        L[naught][i] = alpha[i] * df25519.G
        if naught == 0:
            bbs1[i] = df25519.random_scalar()
            c = df25519.hash_to_scalar(str(L[naught][i]))
            L[prime][i] = bbs1[i] * df25519.G + c * CiH[i]
        L1 += str(L[1][i])

    bbee = df25519.hash_to_scalar(L1)

    for j in range(64):
        if int(b[j]) == 0:
            bbs0[j] = alpha[j] - ai[j] * bbee
        else:
            bbs0[j] = df25519.random_scalar()
            LL = bbs0[j] * df25519.G + bbee * Ci[j]
            cc = df25519.hash_to_scalar(str(LL))
            bbs1[j] = alpha[j] - ai[j] * cc

    return bbee, bbs0, bbs1
#--------------------------------------------------------------------------------------------
### Bulletproofs 
#--------------------------------------------------------------------------------------------
def check_sig_bp1(resp_json):
    proofs = get_vars_bp1(resp_json)
    return check_bp([proofs])
#--------------------------------------------------------------------------------------------
def get_vars_bp1(resp_json):
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

    L = PointVector([Point(one_L_aux) for one_L_aux in L_aux])
    R = PointVector([Point(one_R_aux) for one_R_aux in R_aux])

    a = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["a"])
    b = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["b"])
    t = Scalar(resp_json["rctsig_prunable"]["bp"][ind]["t"])

    V = PointVector([df25519.inv8 * Point(one_outPk_aux) for one_outPk_aux in resp_json["rct_signatures"]["outPk"]])

    return [V, A, S, T1, T2, taux, mu, L, R, a, b, t]
#--------------------------------------------------------------------------------------------
### Bulletproofs Plus
#--------------------------------------------------------------------------------------------
def check_sig_bp_plus(resp_json):
    proofs = get_vars_bp_plus(resp_json)
    return check_bp_plus([proofs])
#--------------------------------------------------------------------------------------------
def get_vars_bp_plus(resp_json):
    ind = 0
    N = 64
    A = Point(resp_json["rctsig_prunable"]["bpp"][ind]["A"])
    A1 = Point(resp_json["rctsig_prunable"]["bpp"][ind]["A1"])
    B = Point(resp_json["rctsig_prunable"]["bpp"][ind]["B"])
    r1 = Scalar(resp_json["rctsig_prunable"]["bpp"][ind]["r1"])
    s1 = Scalar(resp_json["rctsig_prunable"]["bpp"][ind]["s1"])
    d1 = Scalar(resp_json["rctsig_prunable"]["bpp"][ind]["d1"])
    L_aux = resp_json["rctsig_prunable"]["bpp"][ind]["L"]
    R_aux = resp_json["rctsig_prunable"]["bpp"][ind]["R"]

    L = PointVector([Point(one_L_aux) for one_L_aux in L_aux])
    R = PointVector([Point(one_R_aux) for one_R_aux in R_aux])

    V = PointVector([df25519.inv8 * Point(one_outPk_aux) for one_outPk_aux in resp_json["rct_signatures"]["outPk"]])

    return [V, A, A1, B, r1, s1, d1, L, R]
#--------------------------------------------------------------------------------------------
### Functions used in Bulletproofs(+) 
#--------------------------------------------------------------------------------------------
def mash(hcache, s1 = "", s2="", s3="", s4=""):
    cache = hash_to_scalar(str(hcache) + str(s1) + str(s2) + str(s3) + str(s4))
    return cache
#--------------------------------------------------------------------------------------------
def scalar_to_bits(s, N):
    result = []
    for i in range(N - 1, -1, -1):
        if s / Scalar(2**i) == Scalar(0):
            result.append(Scalar(0))
        else:
            result.append(Scalar(1))
            s -= Scalar(2**i)
    return ScalarVector(list(reversed(result)))
#--------------------------------------------------------------------------------------------
def sum_scalar(s, l):
    if not int(l) & int(l - 1) == 0:
        raise ValueError("We need l to be a power of 2!")

    if l == 0:
        return Scalar(0)
    if l == 1:
        return Scalar(1)

    r = Scalar(1) + s
    while l > 2:
        s = s * s
        r += s * r
        l = l // 2
    return r
#--------------------------------------------------------------------------------------------
def exp_scalar(s, l):
    return ScalarVector([s**i for i in range(l)])
#--------------------------------------------------------------------------------------------
def vector_sub(vec, sca):
    return [one_vec - sca for one_vec in vec]
#--------------------------------------------------------------------------------------------
def vector_add(vec, sca):
    return [one_vec + sca for one_vec in vec]
#--------------------------------------------------------------------------------------------
def vec_add_vec(vec, vec2):
    if len(vec) != len(vec2):
        print("Error at vec_add_vec: vector with different lengths")
        return 0
    vec_new = []
    for i in range(len(vec)):
        vec_new.append(vec[i] + vec2[i])

    return vec_new
#--------------------------------------------------------------------------------------------
def sum_of_scalar_powers(x, n):
    res = Scalar(0)
    for i in range(1, n + 1):
        res += x**i
    return res
#--------------------------------------------------------------------------------------------
### Bulletproofs 
#--------------------------------------------------------------------------------------------
def inner_product_bp(data,hash_cache):
    G,H,U,a,b,L,R = data

    n = len(G)
    if n == 1:
        return [a[0],b[0]],hash_cache

    n = n // 2
    cL = a[:n]**b[n:]
    cR = a[n:]**b[:n]
    L = (G[n:]*a[:n] + H[:n]*b[n:] + U*cL)*df25519.inv8
    R = (G[:n]*a[n:] + H[n:]*b[:n] + U*cR)*df25519.inv8

    x = mash(str(hash_cache),str(L),str(R)) #corresponds to w[round]
    hash_cache = copy.copy(x)

    G = (G[:n]*x.invert())*(G[n:]*x)
    H = (H[:n]*x)*(H[n:]*x.invert())

    a = a[:n]*x + a[n:]*x.invert()
    b = b[:n]*x.invert() + b[n:]*x
    
    return [G,H,U,a,b,L,R] ,hash_cache
#--------------------------------------------------------------------------------------------
def prove_bp(sv,gammas):
    N = 64
    M = len(sv)
    MN = M*N

    if (len(sv)!=len(gammas)):
        print("sv and gamma vectors have different lengths.")
        return False

    # curve points
    G = df25519.G
    H = df25519.H
    domain = str("bulletproof")
    Hi = settings_df25519.Hi_df[0:MN]
    Gi = settings_df25519.Gi_df[0:MN]

    # set amount commitments
    V = PointVector([])
    aL = ScalarVector([])
    for i in range(M):
        V.append((H*sv[i] + G*gammas[i])*df25519.inv8)
        aL.extend(scalar_to_bits(sv[i],N))

    strV = "".join([str(one_V) for one_V in V])
    hash_cache = str(hash_to_scalar(strV))

    # set bit arrays
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit-Scalar(1))

    alpha = random_scalar()

    A = (Gi*aL + Hi*aR + G*alpha)*df25519.inv8

    sL = ScalarVector([random_scalar()]*(M*N))
    sR = ScalarVector([random_scalar()]*(M*N))
    rho = random_scalar()
    S = (Gi*sL + Hi*sR + G*rho)*df25519.inv8

    # get challenges
    hash_cache = mash(str(hash_cache),str(A),str(S))

    y = copy.copy(hash_cache)
    y_inv = y.invert()
    z = hash_to_scalar(str(y))
    hash_cache = copy.copy(z)

    # polynomial coefficients
    l0 = aL - ScalarVector([z]*(M*N))
    l1 = sL

    # ugly sum
    zeros_twos = []
    for i in range (M*N):
        zeros_twos.append(Scalar(0))
        for j in range(1,int(M+1)):
            temp = Scalar(0)
            if i >= (j-1)*N and i < j*N:
                temp = Scalar(2)**(i-(j-1)*N)
            zeros_twos[-1] += temp*(z**(1+j))
    
    # more polynomial coefficients
    r0 = aR + ScalarVector([z]*(M*N))
    r0 = r0*exp_scalar(y,M*N)
    r0 += ScalarVector(zeros_twos)
    r1 = exp_scalar(y,M*N)*sR

    # build the polynomials
    t0 = l0**r0
    t1 = l0**r1 + l1**r0
    t2 = l1**r1

    tau1 = random_scalar()
    tau2 = random_scalar()
    T1 = (H*t1 + G*tau1)*df25519.inv8
    T2 = (H*t2 + G*tau2)*df25519.inv8

    x = mash(str(hash_cache),str(z),str(T1),str(T2))
    hash_cache = copy.copy(x)

    x = copy.copy(hash_cache) # challenge

    taux = tau1*x + tau2*(x**2)
    for j in range(1,int(M+1)):
        gamma = gammas[j-1]
        taux += z**(1+j)*gamma
    mu = x*rho+alpha
    
    l = l0 + l1*x
    r = r0 + r1*x
    t = l**r

    x_ip = mash(str(hash_cache),str(x),str(taux),str(mu),str(t))
    hash_cache = copy.copy(x_ip)

    L = PointVector([])
    R = PointVector([])
   
    # initial inner product inputs
    data_ip = [Gi,PointVector([Hi[i]*(y_inv**i) for i in range(len(Hi))]),H*x_ip,l,r,None,None]
    while True:
        data_ip,hash_cache = inner_product_bp(data_ip,hash_cache)

        # we have reached the end of the recursion
        if len(data_ip) == 2:
            return [V,A,S,T1,T2,taux,mu,L,R,data_ip[0],data_ip[1],t]

        # we are not done yet
        L.append(data_ip[-2])
        R.append(data_ip[-1])
#--------------------------------------------------------------------------------------------
def check_bp(proofs):
    N = 64
    # determine the length of the longest proof
    max_MN = 2**max([len(proof[7]) for proof in proofs])

    # curve points
    Z = df25519.Z
    G = df25519.G
    H = df25519.H

    Gi = settings_df25519.Gi_df
    Hi = settings_df25519.Hi_df

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

        # get size information
        M = 2**len(L)//N

        # weighting factors for batching
        weight_y = random_scalar()
        weight_z = random_scalar()

        if weight_y == Scalar(0) or weight_z == Scalar(0):
            raise ArithmeticError

        # reconstruct all challenges
        strV = "".join([str(one_V) for one_V in V])

        hash_cache = str(hash_to_scalar(strV))
        
        y = mash(str(hash_cache), str(A), str(S))

        if y == Scalar(0):
            raise ArithmeticError

        y_inv = y.invert()

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
        for j in range(1,int(M+1)):
            k -= (z**(j+2))*sum_scalar(Scalar(2),N)

        y1 += (t-(z*ip1y+k))*weight_y

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

            z4[i] -= g*weight_z
            z5[i] -= h*weight_z

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
    for i in range(M*N):
        scalars.append(z4[i])
        points.append(Gi[i])
        scalars.append(z5[i])
        points.append(Hi[i])
    
    if not df25519.multiexp_naive(scalars,points) == Z:
        return False
    
    return True
#--------------------------------------------------------------------------------------------
### Bulletproofs Plus
#--------------------------------------------------------------------------------------------
class BulletproofPlus:
    def __init__(self, V, A, A1, B, r1, s1, d1, L, R, seed=None, gammas=None):
        self.V = V
        self.A = A
        self.A1 = A1
        self.B = B
        self.r1 = r1
        self.s1 = s1
        self.d1 = d1
        self.L = L
        self.R = R

        # # NOTE: not public data; here for convenience only
        self.seed = seed
        self.gammas = gammas
#--------------------------------------------------------------------------------------------
class InnerProductRound:
    def __init__(self, Gi, Hi, G, H, a, b, alpha, y, tr, seed):
        # Common data
        self.Gi = Gi
        self.Hi = Hi
        self.G = G
        self.H = H
        self.y = y
        self.done = False
        self.round = 0  # round count

        # Prover data
        self.a = a
        self.b = b
        self.alpha = alpha

        # Verifier data
        self.A = None
        self.B = None
        self.r1 = None
        self.s1 = None
        self.d1 = None
        self.L = PointVector([])
        self.R = PointVector([])

        # Transcript
        self.tr = tr

        # Seed for auxiliary data embedding
        self.seed = seed
#--------------------------------------------------------------------------------------------
def wip_bp_plus(a, b, y):
    if not len(a) == len(b):
        raise IndexError("Weighted inner product vectors must have identical size!")
    if not isinstance(a, ScalarVector) or not isinstance(b, ScalarVector):
        raise TypeError("Weighted inner product requires ScalarVectors!")
    if not isinstance(y, Scalar):
        raise TypeError("Weighted inner product requires Scalar weight!")

    r = Scalar(0)
    for i in range(len(a)):
        r += a[i] * y ** (i + 1) * b[i]
    return r
#--------------------------------------------------------------------------------------------
def inner_product_bp_plus(data):
    n = len(data.Gi)

    if n == 1:
        data.done = True

        # Random masks
        r = random_scalar()
        s = random_scalar()
        d = random_scalar() if data.seed is None else hash_to_scalar(data.seed)
        eta = random_scalar() if data.seed is None else hash_to_scalar(data.seed)

        data.A = (
            data.Gi[0] * r
            + data.Hi[0] * s
            + data.H * (r * data.y * data.b[0] + s * data.y * data.a[0])
            + data.G * d
        ) * df25519.inv8
        data.B = (data.H * (r * data.y * s) + data.G * eta) * df25519.inv8

        data.tr = mash(str(data.tr), str(data.A), str(data.B))
        e = copy.copy(data.tr)

        data.r1 = r + data.a[0] * e
        data.s1 = s + data.b[0] * e
        data.d1 = eta + d * e + data.alpha * e**2

        return

    n = int(n / 2)
    a1 = ScalarVector(data.a[:n])
    a2 = ScalarVector(data.a[n:])
    b1 = ScalarVector(data.b[:n])
    b2 = ScalarVector(data.b[n:])
    G1 = PointVector(data.Gi[:n])
    G2 = PointVector(data.Gi[n:])
    H1 = PointVector(data.Hi[:n])
    H2 = PointVector(data.Hi[n:])

    dL = random_scalar()
    dR = random_scalar()

    cL = wip_bp_plus(a1, b2, data.y)
    cR = wip_bp_plus(a2 * data.y**n, b1, data.y)

    data.L.append(
        (G2 ** (a1 * data.y.invert() ** n) + H1**b2 + data.H * cL + data.G * dL)
        * df25519.inv8
    )
    data.R.append(
        (G1 ** (a2 * data.y**n) + H2**b1 + data.H * cR + data.G * dR) * df25519.inv8
    )

    data.tr = mash(str(data.tr), str(data.L[-1]), str(data.R[-1]))
    e = copy.copy(data.tr)

    data.Gi = G1 * e.invert() + G2 * (e * data.y.invert() ** n)
    data.Hi = H1 * e + H2 * e.invert()

    data.a = a1 * e + a2 * data.y**n * e.invert()
    data.b = b1 * e.invert() + b2 * e
    data.alpha = dL * e**2 + data.alpha + dR * e.invert() ** 2

    data.round += 1
#--------------------------------------------------------------------------------------------
def prove_bp_plus(sv, gamma):
    N = 64
    M = len(sv)
    MN = M * N

    if (len(sv)!=len(gamma)):
        print("sv and gamma vectors have different lengths.")
        return False

    domain = str("bulletproof_plus")

    V = PointVector([])
    aL = ScalarVector([])

    for i in range(M):
        V.append((df25519.H * sv[i] + df25519.G * gamma[i]) * df25519.inv8)
        aL.extend(scalar_to_bits(sv[i], N))

    # set bit arrays
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit - Scalar(1))

    domain_separator_transcript = str("bulletproof_plus_transcript")
    transcript = hash_to_point(
        cn_fast_hash(domain_separator_transcript.encode("utf-8").hex())
    )

    strV = ""
    for i in range(len(V)):
        strV = strV + str(V[i])
    hash_V = str(hash_to_scalar(strV))

    transcript = mash(str(transcript), str(hash_V))

    alpha = random_scalar()

    A = (settings_df25519.Gi_plus_df[0:MN] * aL + settings_df25519.Hi_plus_df[0:MN] * aR + df25519.G * alpha) * df25519.inv8

    y = mash(str(transcript), str(A))

    z = hash_to_scalar(str(y))
    transcript = copy.copy(z)

    d = [Scalar(0)] * MN
    z_squared = z**2
    d[0] = z_squared
    for i in range(1, N):
        d[i] = d[i - 1] * Scalar(2)

    for j in range(1, M):
        for i in range(N):
            d[j * N + i] = d[(j - 1) * N + i] * z_squared

    y_powers = exp_scalar(y, MN + 2)

    aL1 = vector_sub(aL, z)
    aR1 = vector_add(aR, z)
    d_y = []
    for i in range(MN):
        d_y.append(d[i] * y_powers[MN - i])

    aR1 = vec_add_vec(aR1, d_y)

    alpha1 = copy.copy(alpha)
    temp = Scalar(1)
    for j in range(M):
        temp = temp * z_squared
        temp2 = y_powers[MN + 1] * temp
        alpha1 += temp2 * gamma[j]

    seed = None

    ip_data = InnerProductRound(
        settings_df25519.Gi_plus_df[0:64*len(sv)],
        settings_df25519.Hi_plus_df[0:64*len(sv)],
        df25519.G,
        df25519.H,
        aL1,
        aR1,
        alpha1,
        y,
        transcript,
        seed
    )
    while True:
        inner_product_bp_plus(ip_data)

        # We have reached the end of the recursion
        if ip_data.done:
            return BulletproofPlus(
                V,
                A,
                ip_data.A,
                ip_data.B,
                ip_data.r1,
                ip_data.s1,
                ip_data.d1,
                ip_data.L,
                ip_data.R,
                seed,
                gamma,
            )
#--------------------------------------------------------------------------------------------
def check_bp_plus(proofs):

    # curve points
    Z = df25519.Z
    G = df25519.G
    H = df25519.H

    # Weighted coefficients for common generators
    G_scalar = Scalar(0)
    H_scalar = Scalar(0)

    # Batch multiexponentiation is not optimized
    # Final multiscalar multiplication data
    Gi_scalars = ScalarVector([Scalar(0)] * 128*16)
    Hi_scalars = ScalarVector([Scalar(0)] * 128*16)
    scalars = ScalarVector([])
    points = PointVector([])

    # Store auxiliary data
    aux = []

    # Process each proof and add it to the batch
    for proof in proofs:
        if isinstance(proof, BulletproofPlus):
            V, A, A1, B, r1, s1, d1, L, R = proof.V, proof.A,proof.A1,proof.B,proof.r1,proof.s1,proof.d1,proof.L,proof.R
        else:
            V, A, A1, B, r1, s1, d1, L, R = proof

        maxM = 16
        logN = 6
        N = 1 << logN 

        logM = len(L) - 6
        M = 1 << logM
        MN = M * N
        
        if not len(L) == len(R):
            raise IndexError

        # Helpful quantities
        one_MN = ScalarVector([Scalar(1) for _ in range(MN)])

        # Batch weight
        weight = random_scalar()
        if weight == Scalar(0):
            raise ArithmeticError

        # Start transcript
        domain_separator_transcript = str("bulletproof_plus_transcript")
        transcript = hash_to_point(
            cn_fast_hash(domain_separator_transcript.encode("utf-8").hex())
        )

        # Reconstruct challenges
        strV = ""
        for i in range(len(V)):
            strV = strV + str(V[i])
        hash_V = str(hash_to_scalar(strV))

        transcript = mash(str(transcript), str(hash_V))

        y = mash(str(transcript), str(A))
        y_inv = y.invert()

        z = hash_to_scalar(str(y))
        transcript = copy.copy(z)

        if y == Scalar(0):
            raise ArithmeticError("Bad verifier challenge!")
        if z == Scalar(0):
            raise ArithmeticError("Bad verifier challenge!")

        # Start preparing data
        d = ScalarVector([])
        for j in range(M):
            for i in range(N):
                d.append(z ** (2 * (j + 1)) * Scalar(2) ** i)

        # Reconstruct challenges
        challenges = ScalarVector([])  # challenges
        for j in range(len(L)):
            transcript = mash(str(transcript), str(L[j]), str(R[j]))
            challenges.append(transcript)
            if challenges[j] == Scalar(0):
                raise ArithmeticError("Bad verifier challenge!")

        challenges_inv = challenges.invert()

        e = mash(str(transcript), str(A1), str(B))

        while (M <= maxM) & (M < len(V)):
            logM += 1
            M = 1 << (logM)
        rounds = logM + logN
        challenges_cache = ScalarVector([Scalar(0)] * MN)
        challenges_cache[0] = challenges_inv[0]
        challenges_cache[1] = challenges[0]
        for j in range(1, rounds):
            slots = 1 << (j + 1)
            for s in range(slots - 1, 0, -2):
                challenges_cache[s] = challenges_cache[int(s / 2)] * challenges[j]
                challenges_cache[s - 1] = (
                    challenges_cache[int(s / 2)] * challenges_inv[j]
                )

        if e == Scalar(0):
            raise ArithmeticError("Bad verifier challenge!")

        ## Add V terms to multiexp
        for j in range(len(V)):
            scalars.append(weight * (-(e**2) * z ** (2 * (j + 1)) * y ** (M * N + 1)))
            points.append(V[j] * Scalar(8))

        # Add B term
        scalars.append(-weight)
        points.append(B * Scalar(8))

        # Add A1
        scalars.append(-weight * e)
        points.append(A1 * Scalar(8))

        # Add A
        scalars.append(-weight * e**2)
        points.append(A * Scalar(8))

        # Add L_j and R_j
        for j in range(len(L)):
            scalars.append(-weight * (e**2 * challenges[j] ** 2))
            points.append(L[j] * Scalar(8))
            scalars.append(-weight * (e**2 * challenges_inv[j] ** 2))
            points.append(R[j] * Scalar(8))

        # Add G_scalar and H_scalar
        sum_y = sum_of_scalar_powers(y, M * N)
        H_scalar += weight * (
            r1 * y * s1
            + e**2 * (y ** (M * N + 1) * z * one_MN**d + (z**2 - z) * sum_y)
        )
        G_scalar += weight * d1
        scalars.append(G_scalar)
        points.append(G)
        scalars.append(H_scalar)
        points.append(H)

        # Gi_scalars and Hi_scalars
        y_MN = copy.copy(y)
        temp_MN = MN
        while temp_MN > 1:
            y_MN = y_MN * y_MN
            temp_MN /= 2
        y_MN_1 = y_MN * y

        er1wy = e * r1 * weight
        minuse2wy = -(e**2 * weight * y_MN)


        for i in range(MN):
            g_scalar = copy.copy(er1wy)
            g_scalar = g_scalar * challenges_cache[i] + (e**2 * z * weight)

            h_scalar = e * s1 * weight * challenges_cache[(~i) & (MN - 1)] - (
                e**2 * z * weight
            )
            h_scalar += minuse2wy * d[i]

            Gi_scalars[i] += g_scalar
            Hi_scalars[i] += h_scalar

            er1wy = er1wy * y_inv
            minuse2wy = minuse2wy * y_inv

    # Common generators
    for i in range(MN):
        scalars.append(Gi_scalars[i])
        points.append(settings_df25519.Gi_plus_df[i])
        scalars.append(Hi_scalars[i])
        points.append(settings_df25519.Hi_plus_df[i])

    if df25519.multiexp_naive(scalars, points) == Z:
        return True 

    return False 
