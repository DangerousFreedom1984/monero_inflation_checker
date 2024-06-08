
import df25519
from df25519 import (
    Scalar,
    Point,
    PointVector,
    ScalarVector,
    hash_to_point,
    hash_to_scalar,
    random_scalar,
)
import check_clsag
import time


def unit_test_CLSAG():
    msg = str("b3ff9cf9f8bb3cbb2c06dd2cf57628135c1f9cc167334e8ca15efa59aa575211")
    c1 = Scalar('0ae4456e77b83d0d9db87d0a57e1598adb9acd6aa1150d24c31200f74915cc09')
    s = ScalarVector([])
    s.append(Scalar('aa50077dc14ccd44697c059a3d3ef76ff9fd6abe59fb257c5dd6e18c926e1f03'))
    s.append(Scalar('2f6982024875f91ea3b7c552c059b449b060cb261a40eb2d43b3ff41ba545a05'))
    s.append(Scalar('6cf75061bbdd0b2f49c689be8eefbdc38a49b95da94acce8ad11d4e47cb9ab00'))
    s.append(Scalar('3bb179b879e358522026187ac7f30b7402fd7e63ecc21676e4effab801a95901'))
    s.append(Scalar('4176da1f4e99feed1f66e0bd1ac389b698a71da41b7b1d4086c0c2a26b680303'))
    s.append(Scalar('f5b5a0b195d8eee40aaaff25853f08fcbf469deab7c5d460bccdcf43722c820b'))
    s.append(Scalar('59571478017740dfade9e4eb097bf17bdd3ed05e651ba3b481c8d8e1a22e6b00'))
    s.append(Scalar('dfba6231a091243e1d5cb0460904514ca367a218c2e90fd579ca6059ea34110f'))
    s.append(Scalar('27e034fd41777a42cc668b173ad21bb791070434f0ba6111601d0f71027d5b08'))
    s.append(Scalar('73187eaf851573879b3bb6f86276352504f2a35b60b2523ff2e76dcfee616e0b'))
    s.append(Scalar('ec576d03bc8f45c2bf9ea87f3f869fa69208395b5324831f82adb9da1f3e960c'))
    s.append(Scalar('3186cc269852d9a6eb74168efcb5476ab42c817736fc5ff311d2e50609874604'))
    s.append(Scalar('b05f950de1812fded8221a418b0d284e2de013ae2b69482efdcde20f50f2de04'))
    s.append(Scalar('e08ab166933af556761b4dbbf23cc62197d52248c053a46e93ffa3cccfb1dd05'))
    s.append(Scalar('c0616a7c08f06377cee538402c6700235879f34828aa47272dc9ad6aab3ab504'))
    s.append(Scalar('6c4622e466d9893e05713b3421725a9daee514eec826d3e9a03cc9cb6c902d0b'))
    D_aux = Point('9d91ceba34f5bf756420c71cb6b666acdaa7c52223da3489512ddf5139cc5811')
    I = Point('5db6f0c67bc0f3130ded76475096eafb2c0cdb586f622afa78fbbb6ed096046a')
    P = PointVector([])
    P.append(Point('c3aec646609114ab73d1fe4a9e4e53afea4c45c913513a796369c1d3c890c5f3'))
    P.append(Point('6430074a83b834cff7302253c10bbb3319e45cc9cefff3d62f5d209abe090edd'))
    P.append(Point('171ee7d6af0df9fe2cb17fd99d4d45ceb68f1b28474547b592e86693977bf6a4'))
    P.append(Point('c6aaac5c4cf689c2a4c32d1ff496011f5a412575f8a0ef06b333eb7d5803d73e'))
    P.append(Point('81728f03c9ce53844c28200071a38ffc82bf3235e7d0fae161b841fb47acd44e'))
    P.append(Point('c45a333a82cd9d5b91e9cd9b687856fa98f6c8f4c9b9f5186fe545192e121ef8'))
    P.append(Point('7aa59545acf057b0b94e25f495453819a426cca97645a18b21d450fa04e9f749'))
    P.append(Point('390ead8cbe4910b1af2229c956dace85da17414db1fcbaef7817f30e07c6d208'))
    P.append(Point('57f5a3c9d5eb9cb96b7f3d0eb561ad89ee6965ee7996a329a9b7b737355ecfe4'))
    P.append(Point('7b20ad0f25783f7280ae077cffbcfd290e24c7723a7ed5ce874a0232e60b9e8e'))
    P.append(Point('ae781c502340bc05f8641d02a5d0fe2db2c8e505ae0a52be374e1218eec4e538'))
    P.append(Point('a490574db20f3e1e57c74df5921224ae172f6aa3872e4adb217e262f8886e4f0'))
    P.append(Point('1a3027292fc5e0a491dba7b190f53cadf88dc2d8d2253b6b2c020c63302a4f97'))
    P.append(Point('5d0c018d08da79dcd83c9eb8af9db6afd7e78cf41805221498b7962ea33fea00'))
    P.append(Point('ad2af6aaa09af22db438a7f25174253c2ca51f341e18e8906539f0a875cdb8d8'))
    P.append(Point('42d83f8a125d3825d5447a8384825553a4500defba3d7b312266975890e65e00'))
    C_nonzero = PointVector([])
    C_nonzero.append(Point('6c546b93202a8f37b8e86303e2de02aace7f053451107be9fea8c60d5cb89d0b'))
    C_nonzero.append(Point('e12921e1b74a7a449297e964629226be091d279d90c8bb26eeb32a3177f19bf7'))
    C_nonzero.append(Point('01f7bf22602ddbefbab3bc9199a60203f95e5fdf5f082cbe9ff951a55ee8f3a1'))
    C_nonzero.append(Point('c5c274d199f31e6e95d2f1ee638de70b399238d8fb85dd80a72b9a5e05d18bed'))
    C_nonzero.append(Point('73934a70efcbe85fe8d983f0e8bba18d812fd23731e76af611e018e7adb381bd'))
    C_nonzero.append(Point('0157062c1d09af4f8c44f1ec07295b2a687798ffab4ac4f9e9f4be7df15e7f77'))
    C_nonzero.append(Point('c8202e427f011d9d01087cf38faa3321e790ad9538152549bdca59f21f1847f7'))
    C_nonzero.append(Point('275993841b0550298ce24a72c6e520822bea06b294b0cbdeffda2fec2fcb6fb5'))
    C_nonzero.append(Point('7e6ac3af3a09bc5ae6a71dcf22c166a4ecaa3d3b6bca0696726debcec8fc3e8f'))
    C_nonzero.append(Point('8e19ee576135985620df6bd73571578306404772947eeb1e3c93dd0c68a44b44'))
    C_nonzero.append(Point('c79d339f76356b4025232a28f3450f09d7e0c56657538d53c363e33378e46077'))
    C_nonzero.append(Point('cea3294fae6a6c0c4e37c2b1d476bca11cc1b9b3c276cd10f06f6483ea86d4e3'))
    C_nonzero.append(Point('fa9fda347ae5e82f229b8e059dba47b61ae3fc309c1313ee2b8d3ec2f7a7029d'))
    C_nonzero.append(Point('e85a967e5fae9b28c073212b89f7e4b30aaef0b1003a70221ed6f24b632b8128'))
    C_nonzero.append(Point('cc5c7f39324d76e014f6a38460a3754ae9ac02f999fd1dc57f058dbe3970cdb2'))
    C_nonzero.append(Point('47ae7f005386e5d989e58e98f89f7741c4b49352b9d38ebdef13a917ff334573'))
    C_offset = Point('a19c689563de2b8874bcecbf265e7542096d3500a06a5de3883d1fd45960cf9f')

    details = 0


    t1 = time.time()
    res = check_clsag.check_CLSAG(msg, s, c1, D_aux, I, P, C_nonzero, C_offset, details)
    t2 = time.time()
    print("check clsag time: "+ str((t2-t1)*1000) + " ms")

    return res


if __name__ == "__main__":
    clsag_verified = unit_test_CLSAG()
    if clsag_verified[0]:
        print("CLSAG passed!")
    else:
        print("CLSAG failed!")

    import ipdb;ipdb.set_trace()