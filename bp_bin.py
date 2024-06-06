"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

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


def check_sig_Borromean(resp_json, sig_ind):
    P1, P2, bbee, bbs0, bbs1 = get_borromean_vars(resp_json, sig_ind)
    verified, str_out = check_Borromean(P1, P2, bbee, bbs0, bbs1)
    if not verified:
        print(
            "Potential inflation in Borromean Signatures! Please verify what is happening!"
        )
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write(
                "\nPotential inflation in Borromean ring signature! Please verify what is happening!"
            )
        raise Exception("borromean_signature_failure")
    return str_out


def check_commitments(resp_json):
    str_com = ""
    str_com += "\n--------------------------------------------------------\n"
    str_com += "------------------Checking Commitments------------------\n"
    str_com += "--------------------------------------------------------\n"
    if "pseudoOuts" in resp_json["rct_signatures"]:
        Cin = Scalar(0) * df25519.G
        Cout = Scalar(0) * df25519.G
        for i in range(len(resp_json["rct_signatures"]["pseudoOuts"])):
            Cin += Point(resp_json["rct_signatures"]["pseudoOuts"][i])
        for i in range(len(resp_json["rct_signatures"]["outPk"])):
            Cout += Point(resp_json["rct_signatures"]["outPk"][i])
        Fee = Scalar(resp_json["rct_signatures"]["txnFee"]) * df25519.H

        str_com += "Sum of Cin = " + str(Cin)
        str_com += "\n"
        str_com += "Sum of Cout = " + str(Cout)
        str_com += "\n"
        str_com += "Fee = " + str(Fee)
        str_com += "\n"
        res = Cin - Cout - Fee
        str_com += "Result (Cin - Cout - Fee) = " + str(res)
        str_com += "\n"
        if res != df25519.Z:
            str_com += "Inflation may be happening! Commitments do not match!"
            print("Inflation may be happening! Commitments do not match!")
            with open("error.txt", "a+") as file1:
                # Writing data to a file
                file1.write(str(resp_json))
                file1.write(
                    "\nPotential inflation in checking commitments! Please verify what is happening!"
                )
            raise Exception("commitments_failure")
        else:
            str_com += "Commitments match. No inflation is happening."

    else:
        str_com += "Commitments must match in RCTTypeFull transactions. Otherwise the MLSAG ring signature would fail."

    str_com += "\n"
    str_com += "--------------------------------------------------------"
    str_com += "\n"
    return str_com


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


def check_Borromean(P1, P2, bbee, bbs0, bbs1, details=0):
    # t1 = time.time()
    LV = ""
    str_out = "\n"
    str_out += "--------------------------------------------------------\n"
    str_out += "-----------Checking Borromean Ring Signature------------\n"
    str_out += "--------------------------------------------------------"
    str_out += "\n"
    for j in range(64):
        LL = bbee * P1[j] + bbs0[j] * df25519.G
        chash = df25519.hash_to_scalar(str(LL))
        LV += str(chash * P2[j] + bbs1[j] * df25519.G)
        str_out += str("LL = ")
        str_out += str(LL)
        str_out += "\n"

    eeComp = df25519.hash_to_scalar(LV)
    str_out += str("eeComp = ")
    str_out += str(eeComp)
    str_out += "\n"
    # print('Time to check Borromean:', (time.time()-t1))
    res = bbee - eeComp
    str_out += "\n"
    str_out += str("Result: ")
    str_out += "\n"
    str_out += str(res)
    str_out += "\n"
    if res == Scalar(0):
        str_out += "Borromean verification done. Everything is fine."
    else:
        str_out += (
            "Borromean verification failed! There may be some inflation happening!"
        )
    str_out += "\n"
    str_out += "--------------------------------------------------------"
    str_out += "\n"

    return res == Scalar(0), str_out


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


########################## Bulletproofs ###########################


def check_commitments_bp1(resp_json):
    str_com = ""
    str_com += "\n--------------------------------------------------------\n"
    str_com += "------------------Checking Commitments------------------\n"
    str_com += "--------------------------------------------------------\n"
    Cin = Scalar(0) * df25519.G
    Cout = Scalar(0) * df25519.G
    for i in range(len(resp_json["rctsig_prunable"]["pseudoOuts"])):
        Cin += Point(resp_json["rctsig_prunable"]["pseudoOuts"][i])
    for i in range(len(resp_json["rct_signatures"]["outPk"])):
        Cout += Point(resp_json["rct_signatures"]["outPk"][i])
    Fee = Scalar(resp_json["rct_signatures"]["txnFee"]) * df25519.H

    str_com += "Sum of Cin = " + str(Cin)
    str_com += "\n"
    str_com += "Sum of Cout = " + str(Cout)
    str_com += "\n"
    str_com += "Fee = " + str(Fee)
    str_com += "\n"
    res = Cin - Cout - Fee
    str_com += "Result (Cin - Cout - Fee) = " + str(res)
    str_com += "\n"
    if res != df25519.Z:
        str_com += "Inflation may be happening! Commitments do not match!"
        print("Inflation may be happening! Commitments do not match!")
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write(
                "\nPotential inflation in checking commitments! Please verify what is happening!"
            )
        raise Exception("commitments_failure")

    else:
        str_com += "Commitments match. No inflation is happening."

    str_com += "\n"
    str_com += "--------------------------------------------------------"
    str_com += "\n"
    return str_com


def check_sig_bp1(resp_json):
    proofs = get_vars_bp1(resp_json)
    verified, str_out = check_bp1([proofs])
    if not verified:
        print(
            "Potential inflation in Bulletproofs Signatures! Please verify what is happening!"
        )
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write(
                "\nPotential inflation in Bulletproofs ! Please verify what is happening!"
            )
        raise Exception("bulletproof_failed")
    return str_out


def check_sig_bp_plus(resp_json):
    proofs = get_vars_bp_plus(resp_json)
    verified, str_out = check_bp_plus([proofs])
    if not verified:
        print(
            "Potential inflation in Bulletproofs+ Signatures! Please verify what is happening!"
        )
        with open("error.txt", "a+") as file1:
            # Writing data to a file
            file1.write(str(resp_json))
            file1.write(
                "\nPotential inflation in Bulletproofs+ ! Please verify what is happening!"
            )
        raise Exception("bulletproofplus_failed")
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
        V.append(inv8 * Point(outPk_aux[i]))

    return [V, A, S, T1, T2, taux, mu, L, R, a, b, t]


def get_vars_bp_plus(resp_json):
    inv8 = Scalar(8).invert()
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

    L = PointVector()
    for i in range(len(L_aux)):
        L.append(Point(L_aux[i]))

    R = PointVector()
    for i in range(len(R_aux)):
        R.append(Point(R_aux[i]))

    outPk_aux = resp_json["rct_signatures"]["outPk"]
    V = PointVector()
    for i in range(len(outPk_aux)):
        V.append(inv8 * Point(outPk_aux[i]))

    return [V, A, A1, B, r1, s1, d1, L, R]


def check_bp1(proofs):
    N = 64
    # determine the length of the longest proof
    max_MN = 2 ** max([len(proof[7]) for proof in proofs])

    # curve points
    Z = df25519.Z
    G = df25519.G

    domain = str("bulletproof")
    H = df25519.H

    # set up weighted aggregates
    y0 = Scalar(0)
    y1 = Scalar(0)
    z1 = Scalar(0)
    z3 = Scalar(0)
    z4 = [Scalar(0)] * max_MN
    z5 = [Scalar(0)] * max_MN
    scalars = ScalarVector([])  # for final check
    points = PointVector([])  # for final check

    # run through each proof
    for proof in proofs:
        V, A, S, T1, T2, taux, mu, L, R, a, b, t = proof

        # get size information
        M = 2 ** len(L) // N

        # weighting factors
        weight_y = random_scalar()
        weight_z = random_scalar()

        if weight_y == Scalar(0) or weight_z == Scalar(0):
            raise ArithmeticError

        strV = ""
        for i in range(len(V)):
            strV = strV + str(V[i])
        hash_cache = str(hash_to_scalar(strV))

        # reconstruct all challenges
        y = mash(str(hash_cache), str(A), str(S))
        hash_cache = copy.copy(y)

        if y == Scalar(0):
            raise ArithmeticError
        y_inv = y.invert()

        if y == Scalar(0):
            raise ArithmeticError

        z = hash_to_scalar(str(y))
        hash_cache = copy.copy(z)

        x = mash(str(hash_cache), str(z), str(T1), str(T2))

        hash_cache = copy.copy(x)

        if x == Scalar(0):
            raise ArithmeticError

        x_ip = mash(str(hash_cache), str(x), str(taux), str(mu), str(t))
        hash_cache = copy.copy(x_ip)

        if x_ip == Scalar(0):
            raise ArithmeticError

        y0 += -taux * weight_y

        ip1y = sum_scalar(y, M * N)
        k = -(z**2) * ip1y
        # k = (z-z**2)*sum_scalar(y,M*N)
        for j in range(1, int(M + 1)):
            k -= (z ** (j + 2)) * sum_scalar(Scalar(2), N)

        y1 += (t - (z * ip1y + k)) * weight_y

        for j in range(len(V)):
            scalars.append(z ** (j + 2) * weight_y)
            points.append(V[j] * Scalar(8))
        scalars.append(x * weight_y)
        points.append(T1 * Scalar(8))
        scalars.append(x**2 * weight_y)
        points.append(T2 * Scalar(8))

        scalars.append(weight_z)
        points.append(A * Scalar(8))
        scalars.append(x * weight_z)
        points.append(S * Scalar(8))

        # inner product
        W = ScalarVector([])
        for i in range(len(L)):
            W.append(mash(str(hash_cache), str(L[i]), str(R[i])))
            hash_cache = copy.copy(W[i])
            if W[i] == Scalar(0):
                raise ArithmeticError
        W_inv = W.invert()

        for i in range(M * N):
            index = copy.copy(i)
            g = copy.copy(a)
            h = b * ((y_inv) ** i)
            for j in range(len(L) - 1, -1, -1):
                J = len(W) - j - 1
                base_power = 2**j
                if index // base_power == 0:
                    g *= W_inv[J]
                    h *= W[J]
                else:
                    g *= W[J]
                    h *= W_inv[J]
                    index -= base_power

            g += z
            h -= (z * (y**i) + (z ** (2 + i // N)) * (Scalar(2) ** (i % N))) * (
                (y_inv) ** i
            )

            z4[i] -= g * weight_z
            z5[i] -= h * weight_z

        z1 += mu * weight_z

        for i in range(len(L)):
            scalars.append(W[i] ** 2 * weight_z)
            points.append(L[i] * Scalar(8))
            scalars.append(W_inv[i] ** 2 * weight_z)
            points.append(R[i] * Scalar(8))
        z3 += (t - a * b) * x_ip * weight_z

    scalars.append(y0 - z1)
    points.append(G)
    scalars.append(z3 - y1)
    points.append(H)
    for i in range(M * N):
        scalars.append(z4[i])
        points.append(settings.Gi[i])
        scalars.append(z5[i])
        points.append(settings.Hi[i])

    str_out = ""
    str_out += "\n--------------------------------------------------------\n"
    str_out += "------------------Checking Rangeproofs------------------\n"
    str_out += "--------------------------------------------------------\n"
    str_out += "Verifying the Bulletproofs equation with inputs: \n"
    str_out += "\nV: \n"
    str_out += str(V)
    str_out += "\nA: \n"
    str_out += str(A)
    str_out += "\nS: \n"
    str_out += str(S)
    str_out += "\nT1: \n"
    str_out += str(T1)
    str_out += "\nT2: \n"
    str_out += str(T2)
    str_out += "\ntaux: \n"
    str_out += str(taux)
    str_out += "\nmu: \n"
    str_out += str(mu)
    str_out += "\nL: \n"
    str_out += str(L)
    str_out += "\nR: \n"
    str_out += str(R)
    str_out += "\na: \n"
    str_out += str(a)
    str_out += "\nb: \n"
    str_out += str(b)
    str_out += "\nt: \n"
    str_out += str(t)

    str_out += "\n"
    if not df25519.multiexp_naive(scalars, points) == Z:
        raise ArithmeticError("Bad z check!")
        str_out += "Bulletproof check FAILED"
        return False, str_out

    str_out += "Bulletproof passed!"
    str_out += "The value committed represents the true value with a negligible probability otherwise."
    return True, str_out


def check_bp_plus(proofs):

    ti = time.time()

    # curve points
    Z = df25519.Z
    G = df25519.G
    H = df25519.H

    domain = str("bulletproof_plus")

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

    t1 = time.time()
    print("Time until here 1: " + str(t1 - ti))

    # Process each proof and add it to the batch
    for proof in proofs:
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

        t2 = time.time()
        print("Time until here 2: " + str(t2 - t1))
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

    str_out = ""
    # str_out += "\n--------------------------------------------------------\n"
    # str_out += "------------------Checking Rangeproofs------------------\n"
    # str_out += "--------------------------------------------------------\n"
    # str_out += "Verifying the Bulletproofs equation with inputs: \n"
    # str_out += "\nV: \n"
    # str_out += str(V)
    # str_out += "\nA: \n"
    # str_out += str(A)
    # str_out += "\nA1: \n"
    # str_out += str(A1)
    # str_out += "\nB: \n"
    # str_out += str(B)
    # str_out += "\nr1: \n"
    # str_out += str(r1)
    # str_out += "\ns1: \n"
    # str_out += str(s1)
    # str_out += "\nd1: \n"
    # str_out += str(d1)
    # str_out += "\nL: \n"
    # str_out += str(L)
    # str_out += "\nR: \n"
    # str_out += str(R)

    # str_out += "\n"

    t3 = time.time()
    print("Time until here 3: " + str(t3 - t2))

    tbm = time.time()
    print("Time until multiexp: " + str((tbm-ti)*1000))
    # str_out += "Time until multiexp: " + str(time.time() - tbp)
    # import ipdb; ipdb.set_trace()
    # if not df25519.multiexp_naive(scalars, points) == Z:
    if not df25519.multiexp_naive(scalars, points) == Z:
        str_out += "Bulletproof+ check FAILED"
        return False, str_out

    tam = time.time()
    print("Time for multiexponentiation: " + str((tam - tbm)*1000) + str(" in ms."))
    str_out += "Bulletproof+ passed!"
    str_out += "The value committed represents the true value with a negligible probability otherwise."
    # str_out += "Total time to execute: " + str(time.time()-tbp)
    return True, str_out


################### BP functions ##################


def mash(hcache, s1, s2="", s3="", s4=""):
    cache = hash_to_scalar(str(hcache) + str(s1) + str(s2) + str(s3) + str(s4))
    return cache

def clear_cache():
    global cache
    cache = ""

def scalar_to_bits(s, N):
    result = []
    for i in range(N - 1, -1, -1):
        if s / Scalar(2**i) == Scalar(0):
            result.append(Scalar(0))
        else:
            result.append(Scalar(1))
            s -= Scalar(2**i)
    return ScalarVector(list(reversed(result)))


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


def inner_product(data, hash_cache):
    G, H, U, a, b, L, R = data

    n = len(G)
    if n == 1:
        return [a[0], b[0]], hash_cache

    n = n // 2
    cL = a[:n] ** b[n:]
    cR = a[n:] ** b[:n]
    L = (G[n:] * a[:n] + H[:n] * b[n:] + U * cL) * inv8
    R = (G[:n] * a[n:] + H[n:] * b[:n] + U * cR) * inv8

    x = mash(str(hash_cache), str(L), str(R))  # corresponds to w[round]
    hash_cache = copy.copy(x)

    G = (G[:n] * x.invert()) * (G[n:] * x)
    H = (H[:n] * x) * (H[n:] * x.invert())

    a = a[:n] * x + a[n:] * x.invert()
    b = b[:n] * x.invert() + b[n:] * x

    return [G, H, U, a, b, L, R], hash_cache


################### BP PLUS functions ##################


class BulletproofPlus:
    def __init__(self, V, A, A1, B, r1, s1, d1, L, R, seed, gammas):
        self.V = V
        self.A = A
        self.A1 = A1
        self.B = B
        self.r1 = r1
        self.s1 = s1
        self.d1 = d1
        self.L = L
        self.R = R

        # NOTE: not public data; here for convenience only
        self.seed = seed
        self.gammas = gammas


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


def wip(a, b, y):
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


def inner_product(data):
    n = len(data.Gi)

    if n == 1:
        data.done = True

        # Random masks
        r = random_scalar()
        s = random_scalar()
        d = random_scalar() if data.seed is None else hash_to_scalar(data.seed, "d")
        eta = random_scalar() if data.seed is None else hash_to_scalar(data.seed, "eta")

        data.A = (
            data.Gi[0] * r
            + data.Hi[0] * s
            + data.H * (r * data.y * data.b[0] + s * data.y * data.a[0])
            + data.G * d
        ) * inv8
        data.B = (data.H * (r * data.y * s) + data.G * eta) * inv8

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

    cL = wip(a1, b2, data.y)
    cR = wip(a2 * data.y**n, b1, data.y)

    data.L.append(
        (G2 ** (a1 * data.y.invert() ** n) + H1**b2 + data.H * cL + data.G * dL)
        * inv8
    )
    data.R.append(
        (G1 ** (a2 * data.y**n) + H2**b1 + data.H * cR + data.G * dR) * inv8
    )

    data.tr = mash(str(data.tr), str(data.L[-1]), str(data.R[-1]))
    e = copy.copy(data.tr)

    data.Gi = G1 * e.invert() + G2 * (e * data.y.invert() ** n)
    data.Hi = H1 * e + H2 * e.invert()

    data.a = a1 * e + a2 * data.y**n * e.invert()
    data.b = b1 * e.invert() + b2 * e
    data.alpha = dL * e**2 + data.alpha + dR * e.invert() ** 2

    data.round += 1


def scalar_to_bits(s, N):
    result = []
    for i in range(N - 1, -1, -1):
        if s / Scalar(2**i) == Scalar(0):
            result.append(Scalar(0))
        else:
            result.append(Scalar(1))
            s -= Scalar(2**i)
    return ScalarVector(list(reversed(result)))


def exp_scalar(s, l):
    return ScalarVector([s**i for i in range(l)])


def vector_subtract(vec, sca):
    vec_new = []
    for i in range(len(vec)):
        vec_new.append(vec[i] - sca)
    return vec_new


def vector_add(vec, sca):
    vec_new = []
    for i in range(len(vec)):
        vec_new.append(vec[i] + sca)
    return vec_new


def vector_add_vec(vec, vec2):
    if len(vec) != len(vec2):
        print("Error at vector_add_vec: vector with different lengths")
        return 0
    vec_new = []
    for i in range(len(vec)):
        vec_new.append(vec[i] + vec2[i])

    return vec_new


def sum_of_scalar_powers(x, n):
    res = Scalar(0)
    for i in range(1, n + 1):
        res += x**i
    return res


def prove_bp_plus(sv, gamma):
    N = 64
    M = 2
    MN = M * N
    G = df25519.G
    domain = str("bulletproof_plus")
    H = Scalar(8) * Point(cn_fast_hash(str(G)))
    Hi_plus = PointVector(
        [
            hash_to_point(
                cn_fast_hash(
                    str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i)
                )
            )
            for i in range(0, 2 * M * N, 2)
        ]
    )
    Gi_plus = PointVector(
        [
            hash_to_point(
                cn_fast_hash(
                    str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i)
                )
            )
            for i in range(1, 2 * M * N + 1, 2)
        ]
    )
    # set amount commitments
    V = PointVector([])
    aL = ScalarVector([])
    len_data = len(sv)
    for i in range(len_data):
        V.append((H * sv[i] + G * gamma[i]) * inv8)
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

    A = (Gi_plus * aL + Hi_plus * aR + G * alpha) * inv8

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

    aL1 = vector_subtract(aL, z)
    aR1 = vector_add(aR, z)
    d_y = []
    for i in range(MN):
        d_y.append(d[i] * y_powers[MN - i])

    aR1 = vector_add_vec(aR1, d_y)

    alpha1 = copy.copy(alpha)
    temp = Scalar(1)
    for j in range(len(sv)):
        temp = temp * z_squared
        temp2 = y_powers[MN + 1] * temp
        alpha1 += temp2 * gamma[j]

    seed = None

    ip_data = InnerProductRound(
        Gi_plus, Hi_plus, G, H, aL1, aR1, alpha1, y, transcript, seed
    )
    while True:
        inner_product(ip_data)

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

if __name__ == "__main__":

    V = PointVector([])
    V.append(Point('923427796e77df5b553e23d46a5bd18303bde9cbf3d4276a3455ea0e227e5c97'))
    A = Point('3de5877b144109aafc32686ee90f0162cef3835f25886e234a3bfaf7256c177f')
    A1 = Point('db27e1e48ab6efb4433c84fc3f7602e093d347fb9be25e94d6a193ab408e50ee')
    B = Point('afb8376881c5497afaf125fc98bdc562c6625099d63e1b46de70d7fe5d7a02b6')
    r1 = Scalar('21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00')
    s1 = Scalar('3aefdf5d5c959012383ff208742e67b2c41516ba4bc064468cdca5bda4f0240a')
    d1 = Scalar('9351c6530d51b3807cea1cd67b9e7c0f30fd4a6465ed9917effed8673e0f2b09')
    L = PointVector([])
    L.append(Point('aeeb3ec51f8a7e4ea09255d928d3c6ab9232d99b3af9e06e9455a61a43ccb5f4'))
    L.append(Point('e306c4dcc358b1ced8560e132face7203f362ddd1a8a0c0a86661d36ce7fc136'))
    L.append(Point('6c0ceb074889874a9abd22913fe74da05d8782081308bad6a5fdab80dfd88ab6'))
    L.append(Point('89fa461e11a2697f7d37b40beb93b4731b15f6cba2e358ae146ff9e6f539c842'))
    L.append(Point('3b6df197f741db22676d2d7ba86dda5c958294186468bb9a7473e67f9bf2ab8b'))
    L.append(Point('e773322e6bb047291dae4e35c2c517855af121033f3b23fbbff590c7ac4b1693'))
    R = PointVector([])
    R.append(Point('d6efebc0b33845ae143865b6821f8bf715c211f62f3dd976cb346bda729d503d'))
    R.append(Point('bac78011b1d8391e1f86d65412e94410c98366525c2b7db3353cf443b43c8bd8'))
    R.append(Point('62f8e3bcb0ad17553f19c386f829f5f358a90f5f34ee9217a4086290b544b7e3'))
    R.append(Point('5eea37b9f5dfe790c269e9a6bfc813916b35153a69b0a03113a8be7a54ec101b'))
    R.append(Point('a9048f32afa538afab193a3eef426528cfbc03344fbfb5c6fcd4ba4c9a9d80b5'))
    R.append(Point('3ddd3c95247b4f48f532a788c616c2570ac3cf9ffcd04e5373112c36c27fcacf'))

    bp = [V, A, A1, B, r1, s1, d1, L, R]

    t1 = time.time()
    [res,str_out] = check_bp_plus([bp])
    print(str_out)
    print("Time to verify Bp+ : " + str((time.time()-t1)*1000) + str(" ms"))


    scalar = random_scalar()
    t1_op = time.time()
    for i in range(1000):
        scalar*df25519.G
    print("Time to verify op : " + str((time.time()-t1_op)*1000) + str(" ms"))
    
