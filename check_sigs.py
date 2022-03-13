"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

import sys
from dumber25519 import Scalar, Point, PointVector
import dumber25519
import struct


def generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index):
    summ = Scalar(0)
    aba = [Scalar(0) for xx in range(pubs_count)]
    abb = [Scalar(0) for xx in range(pubs_count)]
    # these are the c[i]'s from the whitepaper
    sigc = [Scalar(0) for xx in range(pubs_count)]
    # these are the r[i]'s from the whitepaper
    sigr = [Scalar(0) for xx in range(pubs_count)]
    for ii in range(0, pubs_count):
        if (ii == sec_index):
            kk = dumber25519.random_scalar()
            print('prefix: ')
            print(prefix)

            tmp3 = dumber25519.scalarmultBase(kk)  # L[i] for i = s
            # Random Public key
            aba[ii] = tmp3
            print('aba: ')
            print(tmp3)
            # tmp4 = dumber25519.hash_to_point2(pubs) #R[i] for i = s
            tmp4 = dumber25519.hash_to_point(str(pubs[ii]))
            print('after hashtopoint: ')
            print(tmp4)
            abb[ii] = kk * tmp4
            print('abb: ')
            print(abb[ii])
        else:
            k1 = dumber25519.random_scalar()
            k2 = dumber25519.random_scalar()

            tmp2 = dumber25519.ge_double_scalarmult_base_vartime(
                k1, pubs[ii], k2)  # this is L[i] for i != s
            print('aba: ')
            print(tmp2)
            aba[ii] = tmp2
            tmp3 = dumber25519.hash_to_point(str(pubs[ii]))
            print('tmp3: ')
            print(tmp3)
            abb[ii] = dumber25519.ge_double_scalarmult_vartime(
                k2, tmp3, k1, Point(image))  # R[i] for i != s
            print('abb: ')
            print(abb[ii])
            sigc[ii] = k1  # the random c[i] for i != s
            sigr[ii] = k2  # the random r[i] for i != s
            # summing the c[i] to get the c[s] via page 9 whitepaper
            summ = dumber25519.sc_add(summ, sigc[ii])

    buf = struct.pack('64s', prefix)
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', str(aba[ii]).encode())
        buf += struct.pack('64s', str(abb[ii]).encode())

    #hh is Scalar
    print('buf: ')
    print(buf)
    c = dumber25519.hash_to_scalar(buf.decode())

    sigc[sec_index] = dumber25519.sc_sub(c, summ)  # c[s] = hash - sum c[i] mod l
    # r[s] = q[s] - sec * c[index]
    sigr[sec_index] = dumber25519.sc_mulsub(sigc[sec_index], sec, kk)

    print('sigc: ')
    print(sigc)

    print('sigr: ')
    print(sigr)
    return image, sigc, sigr


def check_ring_signature(prefix, key_image, pubs, pubs_count, sigr, sigc):
    Li = [Scalar(0) for xx in range(pubs_count)]
    Ri = [Scalar(0) for xx in range(pubs_count)]
    str_out = 'Arguments of check_ring_signature: '
    str_out += 'Prefix: ' + str(prefix)
    str_out += '\n'
    str_out += 'Key_image: ' + str(key_image)
    str_out += '\n'
    str_out += 'Public keys: ' + str(pubs)
    str_out += '\n'
    str_out += 'Public keys count: ' + str(pubs_count)
    str_out += '\n'
    str_out += 'Signature r: ' + str(sigr)
    str_out += '\n'
    str_out += 'Signature c: ' + str(sigc)
    str_out += '\n'

    summ = Scalar(0)
    for ii in range(0, pubs_count):
        str_out += 'Calculating Li = ri * G + ci * P   for index = ' + str(ii)
        str_out += '\n'
        Li[ii] = dumber25519.ge_double_scalarmult_base_vartime(
            sigc[ii], pubs[ii], sigr[ii])
        str_out += 'Li calculated for index = ' + str(ii)
        str_out += '\n'
        str_out += str(Li[ii])
        str_out += '\n'
        # print('Li calculated for index = ' + str(ii))
        # print(Li[ii])
        tmp1 = dumber25519.hash_to_point(str(pubs[ii]))
        str_out += 'Calculating Ri = ri * H(P) + ci * I   for index = ' + str(ii)
        str_out += '\n'
        Ri[ii] = dumber25519.ge_double_scalarmult_vartime(
            sigr[ii], tmp1, sigc[ii], Point(key_image))
        str_out += 'Ri calculated for index = ' + str(ii)
        str_out += '\n'
        str_out += str(Ri[ii])
        str_out += '\n'

        # print('Ri calculated for index = ' + str(ii))
        # print(Ri[ii])
        summ = dumber25519.sc_add(summ, sigc[ii])
        str_out += 'Calculating sum (s) = sum(ci) ' + str(summ)
        str_out += '\n'

    buf = struct.pack('64s', prefix)
    for ii in range(0, pubs_count):
        buf += struct.pack('64s', str(Li[ii]).encode())
        buf += struct.pack('64s', str(Ri[ii]).encode())

    str_out += 'Message (prefix+Li+Ri) before hash_to_scalar = ' + str(buf)
    str_out += '\n'
    h = dumber25519.hash_to_scalar(buf.decode())
    str_out += 'Hash of prefix (h): ' + str(h)
    str_out += '\n'
    res = dumber25519.sc_sub(h, summ)
    str_out += 'Subtraction of sum (s) and hash (h): ' + str(res)
    str_out += '\n'
    # print('Result: ')
    # print(res)
    if dumber25519.sc_isnonzero(res) == 0:
        str_out += 'Transaction is valid. The signature matches the data.'
    else:
        str_out += 'Transaction is invalid. The signature does not match the data.'


    return (dumber25519.sc_isnonzero(res) == 0),str_out





if __name__ == "__main__":

    if sys.argv[1] == "gen_ring_sig":

        prefix = b"8ae47e12cca160c1a52e5517f6f1822d2bb6f1a24e8094b78891458f2b3e4d5d"
        image = "f1206393161213a5e4093f9c65e6ef92ca7f21b3513c90e50422e1280ca8165b"
        pubs_array = [
            Point('649f27680aa9cbfb1166d5ad0dd80d20508646442e3e850c0a772a13a4c6b14a')]
        pubs = PointVector(pubs_array)
        pubs_count = 1
        sec = Scalar(
            "568325b113beabab5b8a1643b065f4bae5181c7b2026ea8dfefeff118ba6de0d")
        sec_index = 0

        ima, sic, sir = generate_ring_signature(
            prefix, image, pubs, pubs_count, sec, sec_index)

        print("ima", ima)
        print("sic", sir)
        print("sir", sic)
        # print(check_ring_signature("dest", ima, [Pa, Pb], 2, sir, sic))

    if sys.argv[1] == "gen_ring_sig_mult":

        prefix = b'7f658119722803b0fdab41843d4c3c2510e1cbbe64746255dfbd93b48a380856'
        image = 'e525d54d017780fd439141cf9ec25ffeecdc6a2cb7b60c332c93740b3834bd8e'
        pubs_array = [
            Point('a9e8410fbdee927953160354801f281845e00f8cdd476b5012195854f6d1dfeb'),
            Point('b4493a0bbb5b9968685202619eff663dbc7f95d6baec74b229fbb935d9e88610')]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)
        sec = Scalar(
            'ef0338f3ab4d27b137aa5d82b481e7e1b942f513b1faa8cbbdca8bacadb6bb09')
        sec_index = 0

        ima, sic, sir = generate_ring_signature(
            prefix, image, pubs, pubs_count, sec, sec_index)

        print("ima", ima)
        print("sic", sir)
        print("sir", sic)

    if sys.argv[1] == "check_ring_sig":

        prefix = b'ad19333d6a1e36907f47d2f37904f9fa17557661ff3ff6f3c3207785050e9b59'
        image = '52e8e81fe928a338b92dadfff62baa93055ec82d3891108c8e0a21d2db4316c4'
        # image = 'a855ad897cb46e3e772143e33f1c8cf548ef4139cabab101db673cebe9e27ddc'
        pubs_array = [
            Point('d0a86250c342d8cbcf528fcff880defe0a8116ba5e2db4cfe1aea4dd7102e934'),
            Point('1623db2b826c4b3753d91a91af9542e6b7f3d8d674eefa0c6e9261b9e5867dbe')]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)

        sc = [
            Scalar('2d87a80cf708e6d23b7038b3854d98f4a95ec50647b9e05ef7ad2665c0910d0a'),
            Scalar('0a8b8b3849e3e5d6bf712f263d94f00bbf6abe5ef5f00192e91c83f3461d660f')]
        sr = [
            Scalar('d9697f46b2430cbcbe5a2fc18e0e4c7364c92d90e43e7903bf32eb58c4d4010c'),
            Scalar('bd20e7ec116ec1ab3c3edd0dd003fbfe3e51f1edc66b6061ab6bd0489d86aa09')]

        sigc = dumber25519.ScalarVector(sc)
        sigr = dumber25519.ScalarVector(sr)

        result = check_ring_signature(
            prefix, image, pubs, pubs_count, sigr, sigc)

        print("sic", sigr)
        print("sir", sigc)
        print('Verified: ')
        print(result)

