import dumber25519
from dumber25519 import Scalar, Point, ScalarVector, PointVector, random_scalar, random_point, hash_to_scalar, hash_to_point,cn_fast_hash
import copy
import varint
import numpy as np


cache = '' # rolling transcript hash
inv8 = Scalar(8).invert()

# Add to a transcript hash
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

# Generate a multi-output proof
# data: [Scalar,Scalar] pairs; amount values and masks
# N: number of bits in range
#
# returns: list of proof data
def prove(data,N):
    clear_cache()
    M = len(data)

    print('max_MN prove: ',M*N)
    # curve points
    G = dumber25519.G
    # H = hash_to_point('pybullet H')
    domain = str("bulletproof")
    # H = hash_to_point(cn_fast_hash(strH.encode('utf-8').hex()))
    H = Scalar(8) * Point(cn_fast_hash(str(G)))
    Hi = PointVector([hash_to_point(cn_fast_hash(str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
    Gi = PointVector([hash_to_point(cn_fast_hash(str(H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

    # Gi = PointVector([hash_to_point(cn_fast_hash(('pybullet Gi' + str(i)).encode('utf-8').hex())) for i in range(M*N)])
    # Hi = PointVector([hash_to_point(cn_fast_hash(('pybullet Hi' + str(i)).encode('utf-8').hex())) for i in range(M*N)])

    # set amount commitments
    V = PointVector([])
    aL = ScalarVector([])
    for v,gamma in data:
        V.append((H*v + G*gamma)*inv8)
        # mash(V[-1])
        aL.extend(scalar_to_bits(v,N))

    strV = ''
    for i in range(len(V)):
        strV = strV+str(V[i])
    hash_cache = str(hash_to_scalar(strV))

    # print('V: ')
    # for i in range(len(V)):
        # print(V[i])

    # print('hash_cache: ')
    # print(hash_cache)
    

    # set bit arrays
    aR = ScalarVector([])
    for bit in aL.scalars:
        aR.append(bit-Scalar(1))

    # print('aR: ')
    # for i in range(len(aR)):
        # print(aR[i])

    # print('aL: ')
    # for i in range(len(aL)):
        # print(aL[i])

    # alpha = random_scalar()

    alpha = Scalar('6670e7814fc591f2627b13b3d25fdc2d82f8d653379d7f76bfdaa40c86653908')
    sL = ScalarVector([ Scalar('b9a1ec7165e0999fc16221359cc4921541ab94cf41570097171d06738a3a1b0f'),Scalar('dab32c1007d933eacf43fe2cd12b4dfa42dcc460e2b5611db3c4109b69569005'),Scalar('0734b6f914b1120a1bc2a4fd11bf6d30a3ffcd1601858c7a30a25e90f5609a0a'),Scalar('606133689310d6f95524a1b8009c39ba1e539c6507f02817930d8f69f002f302'),Scalar('1504ae9f8f7a20e420d2ae57ec44535fc4ff0e743b11bd1e13dc0cf19ec0dc0b'),Scalar('ee409eb22adb3ecbb0ebeac3e3d23d49a5afc6d1e0921fbc14ac01a31239fe08'),Scalar('94196e091831306ca2103aa34171e55eb97a7546b3c01921910e7d0ba7a54708'),Scalar('c617ca24f3065cf1d255f5296690ad55aad71e0bbf3b9477907b4ad3c74c1e0b'),Scalar('fa3ce3a6e2364354f3f9b78de104ce20d4350f00b962af02455423ed8ad35400'),Scalar('ba9dc778dbd208f9aca957926564636b48ff211f9bed23c419b087c4ff7fcd01'),Scalar('6d050f709516dd8c9f5a4a9ac294ce9237fc5d955f8625b9434712ca8755d801'),Scalar('170fe3a32b525f8b22d83baec41fd36ce5a2270658de89930cae793bd4e15004'),Scalar('aa4682a7bc067789202d05f0ef4faf7fa9a3f3b7e16af3e0691d9c94ee46cb05'),Scalar('4f680b03d4e8486487c1f937ed65e6c029cdc8d1864ff73e0e39b4a73f44ec01'),Scalar('20f0bb5d047cec98dd9c53e4717fb4fe35bf4344f199249fd019e6a154fff60b'),Scalar('bc2b9c6fcdd4296ca39f02ee2d2859796afd8749e2ec9e3d2f51be17b22ba105'),Scalar('f013ee928cea60e826adacbeab73703454871f5894581983ff68376465b01606'),Scalar('6e9625bc4bf488c42e6ed86db032d354f0de9d8e78b42aa73ac9b499f69b8c02'),Scalar('da87f5f7853ac02202ea7e50f1a0828ced23574af77f876f683443e70c5c8f05'),Scalar('bb026131a16d75ed46d596e48569ddcb9c310d0286e20be8ae8fb12623d7af04'),Scalar('1f6a1167ca3d0586f467bf4d18ab781f4d898826727bf9ee947a0fddf09e6101'),Scalar('1fcd9cbe2e69ae1f42de7c9928d4dac88337bc45b3307f442640bdb7c9541002'),Scalar('22eb36d2d98a8b7318a2f01cea0cc04bd0d2aff227da6718a69108eac9969601'),Scalar('7a86d32e1fd90e8c06a07122026af54a75c554f9f9395abe9586b8a6f2146e05'),Scalar('da648af6202ff9584375894c46bbd2e508dc586525a03159de6ce0ca8ad94102'),Scalar('f5df0dfb8a8b7c655ffeb9dd4cdfaf1b36014afb910fd9f5ef54566f11b24d01'),Scalar('08274b23e4cd8b9f2cee9f14a7039bb818fc0292e4222828021916649076c802'),Scalar('cafb9b43078f471e86a101630be9171e553cadb4152d02d6b4d47788101fee0b'),Scalar('8e942301a05fa3225abac153e7fb18ca56eb1a7ee6e80b334d50bb3621d6980e'),Scalar('1f991ef185fd44bdcf03a886df2635b7ff20150ea4b45929a4f17afa9ae06204'),Scalar('10bd3348945979d8d7087bd71aa1fae8e4af3ea690093da00afaa4c777007b07'),Scalar('ee600b9426b154d7b2eb5c36df6c146e8229537b72e0edee384662a7ced9550c'),Scalar('43dcb280d542a43212fd02154a56b0cb2beff83eae5caac9225946897cbceb0d'),Scalar('649c6aec52f9e333b335e3088e4a833525c6961378299a6ea9d4a5dffbdd2602'),Scalar('833bf0da4fe68d1c10b5d8f97bc5fb65ed5f4e6df83ba5a686e2aa8ab991670c'),Scalar('a8f33ac12cf066f47bb375c4747d74c880b5ab3aa72811105d395a5b10928207'),Scalar('f36cf57738e06068e6ad1ce72f6a95059ff62ca7fefd6b2f0ca02bf0b9086a0f'),Scalar('8478c4d877a833ceb098f013d67879adbdec681d834c31cb24b6b783d3d9420e'),Scalar('4e7b4a08a85777f0117b19b2bba641efee1d88d2b2ff38d1fc531290ed69270b'),Scalar('d6b32be8efdd4f25862e2c6ae9b3d164d097599239ad80fab49d67466466f603'),Scalar('d091dfd77afa74b8b883b8119470341bbeb21df1d062e51f8eb26f75ec874f01'),Scalar('a6259f80afe131ee5f678616574a03b9351985a5b80788391e9752cdf0ed7008'),Scalar('9211779c3f36345899d76968cbd09fe5b0473f706a6e8fc14c98729181a16106'),Scalar('d07df8041dc61f9635d7deb5290397299531c29def46069264643dcdc9fe2401'),Scalar('5ecd2e05287132f8c7b353a00f05c3872fe5a664e6f7f47cfa27b60a17cd4809'),Scalar('31b2849f18b204a18e333e8f29a76db0c737cb309210ee9b8fe9f0f834244500'),Scalar('1005f1c12dac567244a5f5014910575c5b12374bac7c8cd2da10e3d99bbb510f'),Scalar('30df7532518fa95e839180ba69aa0fd6e3e80e0a2beef47e21c2a5a384f05f05'),Scalar('92a9aa9f383f4a86ec28d99e3e33bad58053d7b64cc658600ffb99e833790b04'),Scalar('5e744a363d39ea2a9e437505ecdccf3380d9b005957d7fcfee11c99bb11c090f'),Scalar('7bdfa64a54c71d8189420fe61651740cb181d5b7813fdb09e7fc3e9da437ff03'),Scalar('826574087e013f398ccb3bfd7b9bb7d8ff94f14466d0735a45970f15b04fa809'),Scalar('1988e530b7db7c58ccb1296d4f74d9f7e0ecd07013fc0eda17013bb826829603'),Scalar('db47e8cf0b3745e5b14a6771e063a082273e66f94cf8aba986e3e19c3aaa880d'),Scalar('3ce5ab8795cd789b117adf3befd6ba09645c9b05aca9c485053ad8f9a63dc00b'),Scalar('00699931b21028e0b011c6ff4239f814e079d46c531b29bb3ca27922271cc707'),Scalar('e48c3440a39625b9357b3a2d5867c5cd24241d32cb91ee4b05609e7d22c2d706'),Scalar('22d6b851bccf7e5f8cd56eda0dd9a9d5be389c3c59df4b0f9984d18126d5fa0e'),Scalar('bf0b0b5f5904d2dcdd93d0335a54118e6a054f1514fa2421511b0a1769fd7102'),Scalar('fc9128f6bbb0b575142cd6415776f31fdcf4b15cdc59029b41f9138f2d8a090e'),Scalar('0223520c9120899831c94f72ba4ea980bfb7491f507b9fa9d60f59d2870de10b'),Scalar('ff60c8a7adbbaf550d9d633bb19705de3f2b2762abb8470d167d8f2ed88d490b'),Scalar('831ca00ff5412b58bdc15a68faed648568e2f29c022f754d8b30aebe0ff77008'),Scalar('5f10473be08ee01e308af13ef28e7cdc885576e9fd7d0543ad7d4fd7d7c09003'),Scalar('158bab6ebf34f4592365d8cc1aa4595c4205b1bd7a555002e8e07a01acc0a007'),Scalar('04aa66b69dbbe15215501122489627eff92385d4f4851641fdbf8e8f75635907'),Scalar('3d8fd3e8007b25d9dff08f30e46d92d88562ee285eccb30833b62e0dff583f03'),Scalar('0a3cc78904eb515e64aaebc38baf26dd02f953226549f91c86d5656b73516307'),Scalar('e70e6a30f26050be8713cc9d34a8404eacabddc6de7dd1f2ff5cef5341ee770b'),Scalar('15abdddf05146aebf470e14379222808ac94d380cc972b7b736ff3850fa45d07'),Scalar('cea8eb679db199274b7ad13a5f10a49867c24fe269faf230f1367f97be0f6e0d'),Scalar('288f8929d252d873718d9740d4ea6c4075d854d0bbf7ed88183407812f1b870a'),Scalar('9af1f63bfd70777e80d4a382c5068e3e6ab98e32aab984244a1e3b47ba712508'),Scalar('c5d5aec3b8437c023a36eed8e97bca1db34c256b0ab071980e6309fef07d170a'),Scalar('2aadaf0a6417fefaecb1fc6403b0f6ec0c7196792967ce14a3bedb1a0c619501'),Scalar('1c79af4d2dacd7c94ea829867ad18f62d7b325384042653acbd356e9d8e88403'),Scalar('f80a81c8f01f8016b5d83959fb0885deb036c28adcd30f092ef19f793c89920d'),Scalar('62b9b5d8293006b062db17c253080ef485cba15c58033254dd37a03b485c4306'),Scalar('33f40c5d0b4ff326066097184978bc0679641de1d1beead89de8700674d66301'),Scalar('d878d684322bede4875b2c915e8a41c8836c9843c1ab83751f14eb234e30de07'),Scalar('f6510421c4c55b155c168a989d570e53ed4a94d3b93ffd39d142b9fa33509406'),Scalar('c3c1e8a416ed135f6c26088a4efda98061e5363cfc89a341567712bad63ba204'),Scalar('91936d229ebd9a5f4ec4eaf5e3377905cd242f894f8f82774151db2cc967b20b'),Scalar('3f15a1a3f00743e950ede9f64745806c0ce49c63c19a822c592ae43a98a5d30c'),Scalar('2eb6433902ba1212d4b43a7edc0f1662b8d5609e724ec5251a73e73017d49c07'),Scalar('fa670ba286f12c0b85e6b319d5944be39130884d818a95149448a52632bfea09'),Scalar('3fd3f17dd7daf72f51a81ab881458bfd6968f89b10abb4f2f5d0509602d63f05'),Scalar('60eb049c35cc623f96f7779939ba0acf49f55bc4a4a435157260460b7b00a20a'),Scalar('bfee709b05f8e1e1e729b33f67263770f0a66383e80e9a277c5cb9293e4f0305'),Scalar('7337cc97368aa66a28387559cbcfff6a04e52e50010e54a80b1234402fbbf107'),Scalar('f0023fdd282e6e30ee1ccccecd24a07ebb95759e6905c767d7f5ed183016b300'),Scalar('3b62926e652b64856619c4dd4fb9acbcc5766f1e5319a9995570c320737afb01'),Scalar('e021f44f0b0a06a9b7dfa12d4637d3a0a3019cc1d6acb66df9ce394aae6afa02'),Scalar('386c0500f44b11eaf065a7661097c5ac6935d8af80b5bf1199d6a9ebca1ef000'),Scalar('c164910c78d07028a2135dfba7c94c596650468dc8d0834ae701c1164c30db0d'),Scalar('71f2add410bc1aac61a6f21b066b70ee25c09f09b1ddd82e15d2b20764ca8406'),Scalar('20dc4edc3c506c5e93777ec7cd6448ed8d677f08baff146d4b5711fd3a23a102'),Scalar('8ddf2143372241a828368583f4c1ace1634d96468c1c70ee51b2cd1096c89805'),Scalar('ab77c92ded99af0af026f7bb999665e9a3d0c872c55fe58d84343b743042590c'),Scalar('32fdb9fd63664dc228e638d8ec4a82c6aa833c8b724fbe10f3b0b78d91e7f60a'),Scalar('6726da4ca6cdb49324d8a97e1c1855672bf8ae8380a18ac61bdee49ea8547209'),Scalar('94dfaa7840cb75742834b46ea25d80c15daec3c565a04484427a70153cc2d305'),Scalar('5f147323806e92bf43f51e52361198fed1933cdaea468e41417335e649c41a03'),Scalar('d50acb26a4a61cd1fd62920381c9d7573405d7112113ab755b52ee14915dca03'),Scalar('efa62a6ae2832bd500e7804a6cba8a8d84a44bd66e6bf2e51e90ec39839f6a05'),Scalar('14990efc2e506759602f0285dc4cfa4840d5bc0dda91154adfab4afb7ccade00'),Scalar('c7a9e1a36de7b441bf11f076b5c6cd9d667a2322db842b0d0047e141ee03b00e'),Scalar('7d2c58ab026a923ba8105a182bae7842ead7ef9f51406a38c3d3e01e286ec501'),Scalar('fcb262b84496dd6d050e66a89a2841f893167eb1beae90142dfa431888d31103'),Scalar('04bf5f78affcf3f0938ee19355662647db470109453360b5a65f44e3c4668205'),Scalar('1b1c809aeb70dee16449bacb82066f4a2e1f196c428621c51268f1efc8ce4d0a'),Scalar('4e3138514e1e2d0ecc8b8d20696260643efd5f728d2e2d654751518d21a50f0c'),Scalar('33ef3ad56f87f5541ba6fa4068c0aae3c209a34bc55a78090fbf4f6627a8640f'),Scalar('b4ae46b0bd40b2b1c13b4ca356db5f29e311f7c5cf98838d348853b76390280c'),Scalar('ebdca230a5de2daf4b983a1e7d8abe713fa2c6174f8fe1e3fffe43a4ac519905'),Scalar('728fc22e0f4d422adf303483afdf61b21353047d41517b1d9180af05f9d96903'),Scalar('1fab8c73b2689c59ddc486e81331dae426ece8192c3474780050b54679c28a05'),Scalar('40ee60df49ebe84a2dc57eb9bf195b99cdb201930ab12a316ecbc9cc72bcdb0f'),Scalar('4ed06635caa2d01467640b016e07a56435988afc77c33a84cbb25c21b989d508'),Scalar('00a2b7a2be70e03d758685c28ebcaf1515b1ef2ffb85882935387ae376eb5203'),Scalar('26fccde75a3d592220dd45cafcad80f10716bc83d65a2e99345363ba6fd5050e'),Scalar('91fe34432f1c3386278d567e883e06ed15ad96c5d6beab32e1825c58c5cf670a'),Scalar('da3b299506d8bad77719b746a7d4189d0b075e93c8767fc548a950faa65b250e'),Scalar('a1ffb2bfd518293dbd6f0c4ef31ba31156be552c913929901eceac3834615e00'),Scalar('574ecd48c4d1fa94d5bad6f515fe26456d52d4d290df277ff356c1d53b862f0d'),Scalar('b3c273a39b55fbf162b1773518ae76ffb358113b84f4c7095ace6793cda47109'),Scalar('4f69cc0fbd1f4f7cfc30f8fd7c695e67db5465f58041363142e5ff18ba61900e'),Scalar('3c72da60fe8891702824edcb0c60fc02669fa42255e4ff96a466dca329b48c09'),])
     
    sR = ScalarVector([ Scalar('7a5777af00d53cc7c4a666be7195c0983a147bb310ffd7af99f5d078378d1207'),Scalar('061494199ba52da2ca728a146dd5b94c8f9ed3e61ef2e577019df77888983801'),Scalar('906e43784ce606667a10ad9fe3e3d638f925ee28e428ef4b44b04b28a4868703'),Scalar('46adb0f37c353c1e20d34a11434bf6cb9aa4569a2e85395f8dea40a4cadfdc0c'),Scalar('70d1dfc14c0c058b6a031edbcfbe3d7f637ca214a4400e75dbab17311f53b40e'),Scalar('1b47d1724fcfafa89573b1b6c3910aed6ae722793cc69868f5dc962fff2b040d'),Scalar('5a10904300765614b0728942ed314efd0ebdc68044bc9cc7460800632074e604'),Scalar('b9d5d6304476b498ee297fc60f678047e767605cdca69084d4a92e3efb73d106'),Scalar('99924ae243578464a39f2403801e11eb3959426ff2f0e30da50439748e5b4b0b'),Scalar('29eab421dfe0fd9a86558e52127954afb2b15c2ff3891e02994a1f6facaa2204'),Scalar('f9fa1248577a446d2fbbe148cc796fd23b5bb3c79b960125664679d7bdbfed07'),Scalar('ec545765a47f82a906620578691f4062cb9448702cba3a8caadab84947f7370a'),Scalar('4751ecc5eba94b7be746af84ced5376caf089b6102c5edb99de77cda54db6e01'),Scalar('31343910bcdde2902ea3c5344c06c31d6d1fdd5102cc82bc5a6894d42965e90c'),Scalar('8d765a075d73b1ab2e02f3c4ed72234db68877b8b4c42eaa8004406e4f04dd05'),Scalar('9e7616d276bff22362ba81eaa4fd3ca4654f8e33effa46263a237e51b140ec08'),Scalar('1a71cd268bd0e4e46c7dd84ae57f0a1f7e91d0b32c8a24cdb6f25ef907dd0a0e'),Scalar('48f8f99e9b246983f089737ad465329b0d1287b4c78d7afc1723297ac879f80f'),Scalar('e2d36b990f454dfd6a8b9a859db9141c65d60e93f0ee9dbf1143656f997f490f'),Scalar('c3003123baaa4559add0fa425df3f4abc16a535f9f3780348f5d9665bc245102'),Scalar('46278e9ce74c974004fda2993931fd434433134313d5d0f3b400d6577b2f670d'),Scalar('56e5dc4b8af3710bddbcc4baf3e1620fe59c41798180ab65723e846e429e6d0f'),Scalar('5ece1e6fed6b970fdb253338cd7d5c7d4e19d87a733ad835af7552768520c60a'),Scalar('e613b155a68d38a628f3a5d35d9420d79882e9ca458b8ac802da8233cba3b002'),Scalar('18b08484a9838ad895ca15043d2794ca38f1f8be9b6db73678cf52ceb1d0dd0c'),Scalar('c78a49de9a4a6fb2b4d1d35b0eafe55caacd54423bb399579b098710e30ff906'),Scalar('238e1591a78aa1d5d3251824361caba5fec0efcc1a9a6f974c053b168337910d'),Scalar('b85a83bf394b22edd2d3f69a472e38dc6e2994200b38aa464fd95ec9a90f1d03'),Scalar('0f36a388b447ff4fa3a13ee960d2fcc4cd1cb13667f88d33c7be897ceab1b307'),Scalar('fd9037c3d65a8571a34b5cbe13bc33817f6f9bb592cb76fbca9dcd14c1de650a'),Scalar('8df49c0b89411c942b8a898a14c23152b50d4591f27c55464ced8417630e780f'),Scalar('0f35f88072aefb1787e265023e2625c0e7e4173128d4aa4d587f4d1ad0ada901'),Scalar('73eb54efb5d78064751e1a628bc532468b5f97c71774c8190608cf0185685103'),Scalar('ccbb195cf882a9360e6da8a866eb05aa9261e057916d4875ef9cefa3fb1f0f04'),Scalar('c86755d31ff62938560f162410b6c6222f8768fb6563cc269e5e78cf84eacd08'),Scalar('b6d82e3dc0645a75033f1890abd6441caa159e24a0396f7de0c2658268c63603'),Scalar('639ca46f51c17d64771f57d8a216296c29cc89f02245b12e62efb43934e33a0e'),Scalar('75b81bd6eafdc67284c3814cc75407fda8cda1ec9e3c0d9d2a617be7050b7a00'),Scalar('78a11b0a9fbabd89e5cd8158e93b13a068c4e0186278298200ffa017af241803'),Scalar('8903480ed234a2e91c55baf64140843bfe3951ad1f4e72b727cb2f9c43c19e06'),Scalar('2a8ba8f2f86d22bde9dd34bff98f9c956cc67fa44e90528e4698b02ea3a75505'),Scalar('ef34ab331a0cd8120ea941220231bb9dd6993b8db9cc49c5be264373452adf0b'),Scalar('cf45c944af9e299b3c493c22983040831394edbd72916e87189d9953082bba01'),Scalar('5bd4f162e7bcd3bc69135d0ed9c6f3a5c64a6543cf3ecc34c6c5c66f18ec5800'),Scalar('f7d489614d293ae7774abc2fd046fd02ddd0d35b1288040f964d6a2656d22605'),Scalar('619e40d6bc8d43e1b33f89a0eb83cac671c1544ab2cb579bacd5066a7a563206'),Scalar('e68abd5d30feceb52794663207d4b8a658a59c859818e5585f2b4e5df1c61f05'),Scalar('1a8dc73bae71d6f58b4ce1467127d0caf954d378596ab583c87780f0f2f9070b'),Scalar('75167f14b338cfb50280cf469e7b9f078cd48cd92a24c63f7d2314bfbf26bd00'),Scalar('bad882208ce4f27d90d88ab04b09586a8f5ab44bfd0a0a89f4de0e1ee051340f'),Scalar('3d1894b3892a4ce825cd6747daa7a15e0f6e9a4621ac617c75e2cd2921f86503'),Scalar('8bd12dc1838fc4dd46fc44c361c38fbe11a0b8a8ccaee6ee8b14bcfe5032e40a'),Scalar('52a2a33bf03be198ef6de9eab2361457ced3b33b1f6f6404acd9b62c540de90b'),Scalar('1329a708efea8014ff4cfad6d8f02918550baa146ec99af92020774dc04e6b0f'),Scalar('18dd27a4889d2733c1458a9e1638fcca8aea9cff157850eb7c35d848d2756106'),Scalar('78258dc96891806b8716d22ef7315575a3ec3d5b18e687980a3667bbb98da80f'),Scalar('94d95bb6ea40ae500124233727f599a0d0bd96b29d8b79545850a2131ef5d608'),Scalar('cb971f1a34f3a7d56cb9fa9c8b2a695eb241f09410918eb7f543280372072200'),Scalar('332933bb028e2eb6a3123dbaf50f4147200612a94f2c26d451a6fe519c5e500a'),Scalar('63e57f7c1d1691d6de0cc19b21ad6d7e8de36b5a75f94dd55ef4bb2771e11402'),Scalar('0a4c006e3cde44a98fa72f44a3da2ac03a1e6a2289eeddf732a052fb0884ad06'),Scalar('1585495c647551205d14c76e9cffc67e88dac8f1638fd3495086b2840f55510a'),Scalar('ec56e806ebcf0b004f0756d7815abe1650b519dabe1dc0fc7c48b9dfec8e450c'),Scalar('c6afb210bf4d6a421dbe9ce5fc79e7f65d1d0f8bf2437a5013afbcc72e58ad0b'),Scalar('12faa87945ea77496a6946ac9f5c2b6c19f5b249d0c276e5d9733220924d6c04'),Scalar('1e8dfd18850239cf19da33714969340ff0660d8e24e7d61630663162a5770007'),Scalar('884e9f6dc81b9527d98ee0f03cc633c34fb3fbb5406a4578f35c8eff9dbcc705'),Scalar('f2ed10fda9d921d77ebf6c49d33cdae1a917fa6a4aa5cebbe15a32c21d821904'),Scalar('d48ba914fffe00b6c4f72d865a5ebfc3c707dca19908e02ab72e07d095f23907'),Scalar('ce43bc07f7d9c3f994f986ed9995e4b41d9699e1dbb60fb3bc1b70a06f404309'),Scalar('7e9447b29dfc95123743a8fd9b252246455c1e58aa08820d2a3b1013862b0f08'),Scalar('eaa61b8401cc15f8570520c944b80d6f928a5a18da51a55862d460ce3424eb0b'),Scalar('a15c04dbae48ee11b614cb053a430e12784245ac2d38852c0d177850f10b4d06'),Scalar('8615bde3e9a02473b9a1e48ffc3b908dcbfa89c159ae2e625218a8fae7c1780c'),Scalar('c39cce076187c3725886c08ea26daedff4855aa9190c4efabb9c838c625a4406'),Scalar('6f4dcc405d21fde021c40ebe6cac7e193e843a3e3ccff825c529616b7606cd00'),Scalar('8655f9ec765cba7aa0e2bc231bb086a34871ac5709500569b521ef4caf3e840f'),Scalar('b830926f16cd2aaf1a6253442c84a05657cab39d34d5f0ea77046261df88c500'),Scalar('633780049c3bd4cc13365d1b09b9a2c34064052e3537e9046de8219a74bc5301'),Scalar('6ac1ec71a3921e162876543136b430ce85fd4e07703e5d78154cfad64681f80d'),Scalar('58bca79b08044e4aa8919376016552a8b1fc27564c35601e782a354173ba990e'),Scalar('4955db366a23163a51be1c6d46e73358276fd9ff06dc7dda42a1a2e3a03f3903'),Scalar('f2ce90c062dae53552d69d5a450814f8c2804671c80f7bfce69cc4be124fb904'),Scalar('8ac119d39b7e294d79a6f0b6c1157f98e4201c8fb11971eae29efbf4a35f7901'),Scalar('b486a3ec02827773fa5952b844c7fe38a4eecc0e7713b3ebec956d9925cecc0b'),Scalar('5f99729527812a7f236a46d09d72de0555f280fc8831da7456e828578eaa9f02'),Scalar('64ee880235f54346e29f89c3ea0eb7cad1f2a017de164d208bc9189e8ffd630f'),Scalar('bacf3d30a614f83a8a8d849a0cc52c3f6fc590b11851bb9ea032c8c998c04c03'),Scalar('d756a36d5f1102516c5ca7d4ad35901dcbaa8a4ce607f4d6de799ba8c8162b0e'),Scalar('afd29eb411340dbb97750a964a362a8d2ba9695a4dc458e98fa543323566530c'),Scalar('d16bc75e25144ce1be74286a16dbef14475d74ee95b5b5f9504c0ed96852ed0e'),Scalar('b1cfe14dda8eeb56b25dea26008079328c28aa58afd3fcac7c78c6ff6d8fcf01'),Scalar('e529f327a062255f7c481e8997004af68c20f5c6a90e3d95d1e9b334dcfd9801'),Scalar('170c1a42872662b185a756146ba1984e0ffe55da8389f244ad0bf21fe50e950b'),Scalar('d49f0a470e884d32c8c212d17321ec068d5049d6df1423b4a84e6f868aa0af0f'),Scalar('3390d5f810a42ef6bbf4da52224d51196836674bf7fa6e01629963c083f1d300'),Scalar('5baa84e0d4bf5fc00f716ed10596d7e3bd3056844e3517fab126e4f2997da206'),Scalar('47faedb75aacd46383be52db16b771e4b1b1ac8a50e80ed08d12f04dfaa5d50c'),Scalar('52d02187118b048c0b12951aa87ee2856ec5ca237abfe65f7ffbc1449a623709'),Scalar('85e525c9a38fcfd291a0d72ba8bcc2573438022d2dc8af3ffbaf1d619550290a'),Scalar('2e50a27954a5aa0087f0ab2f5c20cbb414fe4d1c38a1ceb650636d41f4bc4d0a'),Scalar('ec20eaf17ae7d2783b26f78f3261adb628618213f8a0965e63891b5563f5f50e'),Scalar('2fe4ea0f4f66d3adf7189f47bd68d37f5c537f5a84d34dbd3bca4ae0b4d2c309'),Scalar('a9668ee249325665dd08c102a0ac7769385e22af910759796fa004e7d5e38806'),Scalar('4a4ab28d6bdfd69cbe8e0faea3f2824bfc192a38c388d9d93f47c3dd52c4f40f'),Scalar('a87113d3a0a761f5ecece288b234f15d2fb32fa5372ee992ae09e51f24cc7209'),Scalar('5aa11e5eb759767a0b811be2a39493cf413b79377a484e24bdd67c7b7a15e202'),Scalar('12011ec5829c7b72a46aec6ff59743ba0b11e0c799b112dc68c1c7b3b76fee0f'),Scalar('490d93ac56ff9958d2f2f1e5032c04f1d22d7301c355b98220b29d479df6910e'),Scalar('ade3750b557648094f0003a29de70f99bc77f725b427ce1466de4658c459fa0c'),Scalar('2d58f674b13134d05c6490e8976f9c8f7172e5d13eb8edaac8af3b2c1aab120b'),Scalar('945bd264c0aee7067f9f0720c5cefe0200d1e8ae29bc80ee0e39f18ce42c7e07'),Scalar('fb4d69ccfc0a3c5308a0cd373ad98b137d4c5ddafe488904b872457ccae32d0a'),Scalar('b811359321564ae8ae9dda372e1bd25be0957a28add1f3b6d202f95c75bb2701'),Scalar('d8bad483c17bc5601aea1b9037735a2604a7eb21a533efcd7d5ad8d17105c309'),Scalar('30fdd420b54403c3407a0815dd87eb100bc1fadfafa7c0bad399e961747f9506'),Scalar('8d0793f0aa7fd6ebde29a17787c02d63235e0b2213ec1c4220be7688d268b004'),Scalar('21d1b3975365b97e88926700ef5663048bcc0e61244abdad65c836ed32390c06'),Scalar('cc3b63cdfedc068f92f293aaf177f8ecdd2b379a644666e298f100a8b8f8fa0e'),Scalar('b1964b718a0a33528cf6b9e04b36a47ddac9def807d22e28f109c6168f509e06'),Scalar('1f4ea3901566dbbfb2b29debc79ad6f21e4a73c32629fb07341916a68eedc709'),Scalar('ccc1e7d7810a18d0c9b2a736edb27cc4e9293cc0c914887e0ae6979cad42b20f'),Scalar('1696139f937f4b8496c66245dfd4ae1bd6a8b626cf38302f716d616cfe23bf0f'),Scalar('4909a36bc89adb8681bde149ee0a936c28fbfbbdad1cd6a06c96450a6d7d860f'),Scalar('55325a2fbcf30b7469aec622339d1ad03252272aa16f2a5dba5fb939338c2108'),Scalar('4c9d8973c36773d37b5fb92620819f151175471150d951c0cea5c6e3a781b90b'),Scalar('90be4c9624574ff172ece041c057f105aa193fcaac4a621402f82525306b1c0a'),Scalar('55b54cc55fc46a1d65a51076c5625a52d126e26d0ab6e893e1cd77f2236ac008'),])
     
    rho = Scalar('5b382c1dadde9667632880c51d93ba9602c0aa7b1d1e5f5735d488edd6cedc0d')
     
    tau1 = Scalar('d735016a41a486d6a7209be37d71409bc26c0a2c7e16d9c0d89b45828749e90a')
     
    tau2 = Scalar('dba94587ad68fc162887c278aad975681f689e7d1e30c9f8fa29807ceaeb6b08')


    A = (Gi*aL + Hi*aR + G*alpha)*inv8


    print('A: ')
    print(A)

    # sL = ScalarVector([random_scalar()]*(M*N))
    # sR = ScalarVector([random_scalar()]*(M*N))
    # rho = random_scalar()
    S = (Gi*sL + Hi*sR + G*rho)*inv8


    print('S:')
    print(S)

    # get challenges
    hash_cache = mash(str(hash_cache),str(A),str(S))
    # mash(cache,A,S)
    # mash(S)
    y = copy.copy(hash_cache)
    y_inv = y.invert()
    # mash(str(hash_cache),str(y))
    # z = copy.copy(cache)
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

    # tau1 = random_scalar()
    # tau2 = random_scalar()
    T1 = (H*t1 + G*tau1)*inv8
    T2 = (H*t2 + G*tau2)*inv8

    print('T1: ')
    print(T1)

    print('T2: ')
    print(T2)


    x = mash(str(hash_cache),str(z),str(T1),str(T2))
    hash_cache = copy.copy(x)

    # print('x: ')
    # print(x)

    # print('hash_cache: ')
    # print(hash_cache)


    taux = tau1*x + tau2*(x**2)
    for j in range(1,int(M+1)):
        gamma = data[j-1][1]
        taux += z**(1+j)*gamma
    mu = x*rho+alpha
    
    l = l0 + l1*x
    r = r0 + r1*x
    t = l**r

    # print('l: ')
    # print(l)
    # print('r: ')
    # print(r)
    # print('t: ')
    # print(t)

    # print('hash_cache: ')
    # print(hash_cache)

    # print('x: ')
    # print(x)

    x_ip = mash(str(hash_cache),str(x),str(taux),str(mu),str(t))
    hash_cache = copy.copy(x_ip)

    # print('x_ip: ')
    # print(x_ip)


    L = PointVector([])
    R = PointVector([])
   
    # initial inner product inputs
    data_ip = [Gi,PointVector([Hi[i]*(y_inv**i) for i in range(len(Hi))]),H*x_ip,l,r,None,None]
    while True:
        data_ip,hash_cache = inner_product(data_ip,hash_cache)

        # we have reached the end of the recursion

        # import ipdb;ipdb.set_trace()
        if len(data_ip) == 2:
            return [V,A,S,T1,T2,taux,mu,L,R,data_ip[0],data_ip[1],t]

        # we are not done yet
        L.append(data_ip[-2])
        R.append(data_ip[-1])

        # print('L: ')
        # print(L)
        # print('R: ')
        # print(R)
        # print('aprime: ')
        # print(data_ip[0])
        # print('bprime: ')
        # print(data_ip[1])


# Verify a batch of multi-output proofs
# proofs: list of proof data lists
# N: number of bits in range
#
# returns: True if all proofs are valid
def verify(proofs,N):
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


        for j in range(M):
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
    
    res = dumber25519.multiexp(scalars,points)
    import ipdb;ipdb.set_trace()
    if not dumber25519.multiexp(scalars,points) == Z:
        raise ArithmeticError('Bad z check!')

    return True






data = [ [Scalar('a4e8c2befb1f0000000000000000000000000000000000000000000000000000'),Scalar('2feae0888c1275ee09ba0aa5b094228c522afa3f66fc6471ad03a0a9f6d5450a')],[Scalar('00a0724e18090000000000000000000000000000000000000000000000000000'),Scalar('b82b73afbca21ed29a9e4769e4385b2119d30656efc7b8c8135e59d88314ed0d')],]
 
 



M = 2
N = 64
# proof = prove(data,N)
# np.save('proof.npy',proof)
# proof2 = np.load('proof.npy',allow_pickle=True)

A = Point('ef32c0b9551b804decdcb107eb22aa715b7ce259bf3c5cac20e24dfa6b28ac71')
S = Point('e1285960861783574ee2b689ae53622834eb0b035d6943103f960cd23e063fa0')
T1 = Point('4ea07735f184ba159d0e0eb662bac8cde3eb7d39f31e567b0fbda3aa23fe5620')
T2 = Point('b8390aa4b60b255630d40e592f55ec6b7ab5e3a96bfcdcd6f1cd1d2fc95f441e')
a = Scalar('0077c5383dea44d3cd1bc74849376bd60679612dc4b945255822457fa0c0a209')
b = Scalar('fe80cf5756473482581e1d38644007793ddc66fdeb9404ec1689a907e4863302')
t = Scalar('40dfb08e09249040df997851db311bd6827c26e87d6f0f332c55be8eef10e603')
taux = Scalar('5957dba8ea9afb23d6e81cc048a92f2d502c10c749dc1b2bd148ae8d41ec7107')
mu = Scalar('923023b234c2e64774b820b4961f7181f6c1dc152c438643e5a25b0bf271bc02')

V = PointVector([ Point('8e8f23f315edae4f6c2f948d9a861e0ae32d356b933cd11d2f0e031ac744c41f'),Point('2829cbd025aa54cd6e1b59a032564f22f0b2e5627f7f2c4297f90da438b5510f'),])
L = PointVector([ Point('c45f656316b9ebf9d357fb6a9f85b5f09e0b991dd50a6e0ae9b02de3946c9d99'),Point('9304d2bf0f27183a2acc58cc755a0348da11bd345485fda41b872fee89e72aac'),Point('1bb8b71925d155dd9569f64129ea049d6149fdc4e7a42a86d9478801d922129b'),Point('5756a7bf887aa72b9a952f92f47182122e7b19d89e5dd434c747492b00e1c6b7'),Point('6e497c910d102592830555356af5ff8340e8d141e3fb60ea24cfa587e964f07d'),Point('f4fa3898e7b08e039183d444f3d55040f3c790ed806cb314de49f3068bdbb218'),Point('0bbc37597c3ead517a3841e159c8b7b79a5ceaee24b2a9a20350127aab428713'),])
R = PointVector([ Point('609420ba1702781692e84accfd225adb3d077aedc3cf8125563400466b52dbd9'),Point('fb4e1d079e7a2b0ec14f7e2a3943bf50b6d60bc346a54fcf562fb234b342abf8'),Point('6ae3ac97289c48ce95b9c557289e82a34932055f7f5e32720139824fe81b12e5'),Point('d071cc2ffbdab2d840326ad15f68c01da6482271cae3cf644670d1632f29a15c'),Point('e52a1754b95e1060589ba7ce0c43d0060820ebfc0d49dc52884bc3c65ad18af5'),Point('41573b06140108539957df71aceb4b1816d2409ce896659aa5c86f037ca5e851'),Point('a65970b2cc3c7b08b2b5b739dbc8e71e646783c41c625e2a5b1535e3d2e0f742'),])


proof = [V,A,S,T1,T2,taux,mu,L,R,a,b,t]


res = verify([proof],N)
import ipdb;ipdb.set_trace()
# sv = ScalarVector([ Scalar('7d1948df581b0000000000000000000000000000000000000000000000000000'),Scalar('00a0724e18090000000000000000000000000000000000000000000000000000'),
 
# gamma = ScalarVector([ Scalar('5e77a35f3b1366ec3de6052aa0d18e183972fe117bfdbd10571289c0c3ef2004'),Scalar('5bb46cfaa3ee7615744c0bec73333c49f62ee733f4feaabe67dfc51cf0e0c308'),


