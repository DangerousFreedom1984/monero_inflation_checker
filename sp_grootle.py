import dumber25519
from dumber25519 import (
    Scalar,
    Point,
    PointVector,
    ScalarVector,
    hash_to_point,
    hash_to_scalar,
    random_scalar,
    cn_fast_hash,
)
import copy
import misc_func
import varint_mic as varint
import pyblake2
import nacl.bindings
import sp_classes


def grootle_matrix_commitment(x, M_priv_A, M_priv_B):
    n = len(M_priv_A[0])
    m = len(M_priv_A)

    scalars = ScalarVector([])  # for final check
    points = PointVector([])  # for final check

    scalars.append(x)
    points.append(dumber25519.G)
    n = len(M_priv_A[0])
    m = len(M_priv_A)

    for j in range(m):
        for i in range(n):
            scalars.append(M_priv_A[j][i])
            points.append(G_sp.at_index(2 * (j * n + i)))

    for j in range(m):
        for i in range(n):
            scalars.append(M_priv_B[j][i])
            points.append(G_sp.at_index(2 * (j * n + i) + 1))

    return scalars, points


# M: Vector of Commitments
# l: secret index of M
# C_offset: offset for commitment to zero at index l
# privkey: private key to commitment to zero M[l] - C_offset
# n,m: decomp input set n**m
# message: message to insert in Fiat-Shamir transform hash


def grootle_prove(M, l, C_offset, privkey, n, m, message):
    N = n**m
    C_zero_reproduced = M[l] - C_offset
    if privkey * dumber25519.G != C_zero_reproduced:
        print("Wrong commitment private key")
        return 0

    proof = sp_classes.grootle_proof(m, n)

    rA = random_scalar()
    rB = random_scalar()

    a_m = misc_func.scalar_matrix(n, m, 0)
    a_sq = misc_func.scalar_matrix(n, m, 0)

    for j in range(m):
        a_m[j][0] = Scalar(0)
        for i in range(1, n):
            # a
            a_m[j][i] = random_scalar()
            a_m[j][0] = a_m[j][0] - a_m[j][i]
            # print(a_m[j][0])

            # -a**2
            a_sq[j][i] = Scalar(-1) * a_m[j][i] ** 2

        a_sq[j][0] = Scalar(-1) * a_m[j][0] ** 2

    do_scalars, do_points = grootle_matrix_commitment(rA, a_m, a_sq)

    # for i in range(len(do_scalars)):
    # print('Scalar: ')
    # print(do_scalars[i])

    # for i in range(len(do_points)):
    # print('Points: ')
    # print(do_points[i])

    proof.A = dumber25519.multiexp(do_scalars, do_points)

    # Commit to decomposition bits: sigma, a*(1-2*sigma)
    decomp_l = dumber25519.decompose(l, n, m)
    sigma = misc_func.scalar_matrix(n, m, 0)
    a_sigma = misc_func.scalar_matrix(n, m, 0)

    for j in range(m):
        for i in range(n):
            # sigma
            sigma[j][i] = dumber25519.kronecker_delta(decomp_l[j], i)

            # a*(1-2*sigma)
            a_sigma[j][i] = a_m[j][i] * (Scalar(1) - Scalar(2) * sigma[j][i])

    da_scalars, da_points = grootle_matrix_commitment(rB, sigma, a_sigma)

    # for i in range(len(do_scalars)):
    # print('Scalar: ')
    # print(da_scalars[i])

    # for i in range(len(do_points)):
    # print('Points: ')
    # print(da_points[i])

    proof.B = dumber25519.multiexp(da_scalars, da_points)

    proof.A = Scalar(8).invert() * proof.A
    proof.B = Scalar(8).invert() * proof.B

    # print('A/8 = ')
    # print(proof.A)

    # print('B/8 = ')
    # print(proof.B)

    # One-of-many sub-proof: polynomial 'p' coefficients
    p = misc_func.scalar_matrix(N, m + 1, 0)
    pre_convolve_temp = misc_func.scalar_matrix(2, 0, 0)

    for k in range(N):
        decomp_k = dumber25519.decompose(k, n, m)
        # print('decomp_k')
        # print(decomp_k)

        for j in range(m + 1):
            p[k][j] = Scalar(0)

        p[k][0] = a_m[0][int(decomp_k[0])]
        p[k][1] = dumber25519.kronecker_delta(decomp_l[0], decomp_k[0])

        for j in range(1, m):
            pre_convolve_temp[0] = a_m[j][int(decomp_k[j])]
            pre_convolve_temp[1] = dumber25519.kronecker_delta(decomp_l[j], decomp_k[j])

            # print('pre_convolve_temp[0]'+str(pre_convolve_temp[0]))
            # print('pre_convolve_temp[1]'+str(pre_convolve_temp[1]))

            p[k] = dumber25519.convolve(p[k], pre_convolve_temp, m)

    rho = []

    data_x_scalars = ScalarVector([])  # for final check
    data_x_points = PointVector([])  # for final check

    for j in range(m):
        rho.append(random_scalar())

    for j in range(m):
        data_x_scalars = ScalarVector([])  # for final check
        data_x_points = PointVector([])  # for final check
        for k in range(N):
            data_x_scalars.append(p[k][j])
            data_x_points.append(M[k] - C_offset)

        proof.X[j] = rho[j] * dumber25519.G + dumber25519.multiexp(
            data_x_scalars, data_x_points
        )

    for j in range(m):
        proof.X[j] = Scalar(8).invert() * proof.X[j]
        # print('X = '+str(proof.X[j]))

    # TODO compute challenge
    xi = Scalar("db13527ab8397fc0a4e528c1e9af94c9a9634c5a2e02855cf92acf56087b8900")

    xi_pow = dumber25519.powers_of_scalar(xi, m + 1, 0)

    for j in range(m):
        for i in range(1, n):
            proof.f[j][i - 1] = sigma[j][i] * xi + a_m[j][i]
            # print('F['+str(j)+']['+str(i-1)+ '] = '+str(proof.f[j][i-1]))

    proof.zA = rB * xi + rA
    # print('zA')
    # print(proof.zA)

    proof.z = privkey * xi_pow[m]

    for j in range(m):
        proof.z -= rho[j] * xi_pow[j]

    # print('z')
    # print(proof.z)

    return proof


def grootle_verify(proofs, M, proof_offset, n, m, messages):
    # TODO compute challenge
    xi = Scalar("db13527ab8397fc0a4e528c1e9af94c9a9634c5a2e02855cf92acf56087b8900")

    weight1 = random_scalar()
    weight2 = random_scalar()

    scalars = ScalarVector([])  # for final check
    points = PointVector([])  # for final check

    N = n**m

    minus_xi_pow = dumber25519.powers_of_scalar(xi, m + 1, 1)

    A8 = Scalar(8) * proof.A
    B8 = Scalar(8) * proof.B

    X8 = misc_func.point_matrix(m, 0, 0)

    for j in range(m):
        X8[j] = Scalar(8) * proof.X[j]

    f = misc_func.scalar_matrix(m, n, 0)
    for j in range(m):
        f[j][0] = xi
        for i in range(1, n):
            f[j][i] = proof.f[j][i - 1]
            f[j][0] -= f[j][i]

    scalars.append(weight1 * proof.zA)
    points.append(dumber25519.G)

    for j in range(m):
        for i in range(n):
            w1ftemp = weight1 * f[j][i]

            scalars.append(w1ftemp)
            points.append(G_sp.at_index(2 * (j * n + i)))

            scalars.append((xi - f[j][i]) * w1ftemp)
            points.append(G_sp.at_index(2 * (j * n + i) + 1))

    w1minus = Scalar(-1) * weight1

    scalars.append(w1minus)
    points.append(A8)

    scalars.append(w1minus * xi)
    points.append(B8)

    w2sum = Scalar(0)

    for k in range(N):
        w2tk = copy.copy(weight2)
        decomp_k = dumber25519.decompose(k, n, m)

        for j in range(m):
            w2tk = w2tk * f[j][decomp_k[j]]

        w2sum += w2tk

        scalars.append(w2tk)
        points.append(M[k])

    scalars.append(Scalar(-1) * w2sum)
    points.append(proof_offset)

    for j in range(m):
        scalars.append(weight2 * minus_xi_pow[j])
        points.append(X8[j])

    scalars.append(Scalar(-1) * weight2 * proof.z)
    points.append(dumber25519.G)

    if dumber25519.multiexp(scalars, points) != dumber25519.Z:
        print("Grootle proof failed")
        return False
    else:
        print("Verification is correct")
        return True


G_sp = sp_classes.sp_generators()

M = PointVector(
    [
        Point("4e5962db310865eb1f8a404cd89578907578ce902b328d76a3848934379271d0"),
        Point("dda19cc4cd1d693ee1cf502ba286b87ce2a3629319a2c98fabbe802de681b148"),
        Point("c5e4b20c80cb007f73e385d9ddb5dd9d5769daf25e48e7e3a61521006910433f"),
        Point("7b03f30c6860dee10619f16eb08551ca2b0b750d093072d53a86b6620ad0554c"),
    ]
)
C_offset = Point("116cb065ca45c0979a7bc65015ea07b338c71dcc72469dc2823b20ece982b4b5")
privkey = Scalar("8ea10df6841d18534a3797cc923e4018bcbfea62bfe87887fcf9568678a75206")
message = Scalar("5c407eebc154fb27758977c62c67eba6390be6d13aa62bd8120db55342274d03")
l = 0
m = 2
n = 2


proof = grootle_prove(M, l, C_offset, privkey, n, m, message)
grootle_verify(proof, M, C_offset, n, m, message)
