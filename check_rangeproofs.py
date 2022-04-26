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
        str_com = ''
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




# ai =  ScalarVector([Scalar('31e8e973a92660fb77411e1aa2e0613c67de3427af5310ff4019a0bbe328970a'),Scalar('74b957c45fd00586bffd69da78d2ecb8394c49ec8917afbaccb062df2370d10a'),Scalar('0d6039a300d62140e9882bf014f5fddaf57c06f2c94d3c38042c0530717c3c03'),Scalar('a159d232b162812aad7f5db2f56529cf975cb60045b0a7af6c46ccaef8d8cb0e'),Scalar('e0e850d2beeac78167ec3da556750a362a8a0059e45e3c8c3277d91a640f8803'),Scalar('a8314694b74517602f4df4122a5d5a09b394c047f5390aed4d0daaeea9c95003'),Scalar('dddcf333016f20c631e0534fd76ecf36536d89d99e19d856fa4e16c08a260909'),Scalar('93f5b834303cb511b76b728b56180f7a451d82ce6504714180c3f99163981600'),Scalar('22839d54a07f87e1bc0e56581e5945df2a4a22e4453e4c9b89cffa509182c70e'),Scalar('518fe700774f583b0f47b6a07897112996e2307f7530a7371b490e6f8efd1104'),Scalar('da2cece9eaacfeb03b5290da44b53ff8f0507cf87e4a4b3b5a46fc6540814a09'),Scalar('ed919594606b2540f9f41cf568bc93f7008bfc9b0277167fdb2386fef8333d0f'),Scalar('848eee21e6a5f5c628381d5c7480793507663b8bef04d89ee326bc1f45871001'),Scalar('211109e88a770ed0eb7435faed724c335d49ad2eec387f61c5aabf8b4e5ee90f'),Scalar('80200269fa25c93806de2ee21ad48bfc6edb482fa695391202d29a5fb1ff910d'),Scalar('7b5d64d3673feb73d2e9f8598b690f12270869bd1503812fd60122600e20d405'),Scalar('e19b75ad4826b305ef5e4e917c34e4e09d6fa1efbd65f74c5ac4975e9874c304'),Scalar('bb2be9195789db32dfb2c6eeddd6c5a3ad8af0c40a667933b3f4beb8ef189f00'),Scalar('50ec78937b20cdfe3ef39953455ba1bca118deb108e32ceeab96517c2cbd740a'),Scalar('58a3984da41880c3c0d302df41d7fbb36733c8cccbf258a15ba012cc8ef13607'),Scalar('706502c1774d9f478bda5c823c87bd354dfb8cebc1a18e2a3182fb4797632c05'),Scalar('d00ed1e29a14958e62f35ed5f1755f93ba507e5078353e2f2c09706df409df04'),Scalar('d1238a8ef68657f9e0599c21a90e257102ade63686ec2edf7524129cf9715f01'),Scalar('ce15b635bfff3b3259e3d1427ddccc8b4ca8553e8623d232ed549304fb54e708'),Scalar('88dc65a925d9d6d2e6561b572fb236a133564b9f7daacc7a40c817cab664170a'),Scalar('449c90eca9eb37247de83c40897d1ef64c4dafc121d866e18b93b85d38e45700'),Scalar('abfff6b9678fef29db096ef78740373fc1c048d3e9f94f9e9473bf8fc84fec08'),Scalar('4e788552172402586b0a4fc717730c29aa4c36e9e52028db2df042d5721cf20f'),Scalar('3fc465de4570e1a566fbd24890692aabb93d07509e3bccda05fa5b3c4737260b'),Scalar('852c130aa7b6544b82b83fce4ac41cec0fe0aeb68e09b45b866128332ba36c0d'),Scalar('6b2723fcfb787a219fb9be8f095e0ab49b8c2d7f99689e8e95b78098757f9f0d'),Scalar('746bb1ec980f3eabe4dda078e30ead620ff0ee2c511962b0747bb40c6946f300'),Scalar('903d520955feb1cfca1373739256d849e23184a9012e4f54e9a08fc745141b05'),Scalar('413bb35047b33398322633fff715faa667326d05b56b6d974e071bdc1be23709'),Scalar('a2a1dc60cd5b3888c1f58ac724f1fd61865dd1068571481685172cc1072dca0a'),Scalar('7e5e993bc520841c77751edcd3f7110c1af94b06a423e4961ee2d71722190b04'),Scalar('b0659fb7b7555bfee169c8a84719820eb9254765c879c42d093287135ef8c000'),Scalar('2b91a58f12635829768ecb20cf18fb7e88f673281ce066be26c4b15448fd5902'),Scalar('a3b5352eb58d076c665faa3aa4f01a8d0b3e6a7624d78f08ab8e83deca12bc0f'),Scalar('7a0d30236f597ce6640757a501504c91703429b6e99fe8e4decede6041ccd504'),Scalar('cc5ab38561cb09f98342f3af7bc1adc8b624820986843ef8c057042655589c0d'),Scalar('c9e2056b5644741d773d44105afacc206d039511f6623466661f4340a32be00f'),Scalar('37a7dc10ac40810a64bca8b37cccefd3a58f953ea0a2e2790eb0194368232602'),Scalar('066ef80d1a8ed35b4f001c8343d4acc391f151376de8c6e0556de90430ff490b'),Scalar('fa03fd08e2a236366d09e291a486389e6844f88918ae5fcd2290507fe991a509'),Scalar('95478138e509fe4552df11095ffec2fcc315c762f06c7b6ce762c2d28ed29b04'),Scalar('498a51fb37431c669ca7010ccd9a99f0c5e9ba1ef55bab10f256780434ddaf0d'),Scalar('06363c6f8eda5c610a8ba6ce2157280c17b4f6472614320be121cd0ddd5f670a'),Scalar('3d114496acd7a93d66185a359654c22b6615170ff99b9758997bdc04aee21304'),Scalar('ed4b59bbac87b1b5930986789a4e38fd9fb88de1606f26fcb9add47bb454c306'),Scalar('ecb21053fbc3fbac4401c77eec410752ed1ac3635bd11745700d89901c499d00'),Scalar('b17c1ae4c8243efda39b5350c1f02a6bcc368265e8836e39c7b204dfd43ba900'),Scalar('61cff22ee225413b00c328983c2afb3bafd0f8ab8179ce73b02cb311c8338b06'),Scalar('53cca2971deaef2a140b954f4b6424bcf060a537c39b3d6e4490370056f48a0b'),Scalar('9260d69d32d38875d9b19a604a00b558463df8faf92a0d169a8c32ea731a8f0d'),Scalar('5fb932c693ebcda1de2cf1a3fb31b5d3044eb8ca071c0bab024f2a53bf26a607'),Scalar('8a4f4513eb13c5300839c311a54033f3f6418c9d18f858297a3f315d377ea80c'),Scalar('2bf955bbed082cb63f49f7707ef4790518fcf46f66ea0bf476594edfbd2f010e'),Scalar('4d559edd2a7035abe4e09da97c900b72cefe746235a79a14cd1903dc39c56907'),Scalar('71ecc4b6c26e36868b390552dcd0e6652475ee999fd68705938ae0843ce44b01'),Scalar('5136da772ac4f3de8ba79c0d0a52fc1c57c6c1724fb6a14bb3f92f4333f42c02'),Scalar('3c0bdd291d329a114d3c668e208ce3276b8f0fa14f16178ff0f0ef2f97515901'),Scalar('5de08447e97bbc23f7b8ad25cad0bcdd23426ecb692c1d35cae5e943320c2106'),Scalar('7b074fb2b2da5425af7bdfe56ab16940a60b8b03bcb663c1d7113b2f1a3ac404')])


# Ci = PointVector([Point('45dad70a0b2d5d112656a308c0c601abd5ea55cb0e3ecb36e82329a41968a7be'),Point('9c038c6122162cf6716b2afd15e183c1f31372984b0036483780d0b1772849ba'),Point('4bdbcef1a675c51b572dd68dda2cffb8304bc91085811c4b65ef8ecb68b416be'),Point('557b24a6d0a7f198c0bb97a31d8b805f8969b31139901b61f341890634480b13'),Point('511219d71f7b1fc4b09a3cc65378a78ed64575082524502794e74ae00387a7cd'),Point('10ec3103d8ec01d46bb15305555ab03b639ab22f13caeb15326b2187910a6f7d'),Point('2358c2ca61cc4c14a8c1b5d22d68ad9832c343202a51541eb930658ebd944eb0'),Point('b4d79f87b2579cb98297d55e288589ebaf9faaf7903cd866d1bc2cd783624949'),Point('0d120c1f28601cb9840140cc54abacce0c2723b0955f1383025adea0152103c4'),Point('33cf57994fa6e7f8bec0e0d2ff740623fc5782c38a9732d021c59d5fa2211a75'),Point('3097c57c497a29f0b444c099ebf3753adeab8b9fd9c9b317301681c92263623d'),Point('97db38f6f7013d1a74ae5dc9d29d2096f9c4104746c5f390840dff086b4940dd'),Point('60b4b3c0ef2e61fb249bf1974bdbf2ec249f2d22b29db06b1b429cd73d31027f'),Point('0f0d6dcd212534965337b9561a71b1677e90932c995617c8c7d034a7c13d87a2'),Point('4c391c5d2800ae8fe65dd0af8a48343f7390bd090f81f499892d637ed4522a32'),Point('83464feeda9c916340a85878524f122ff1176f3569cb94107db33c9516ff80bc'),Point('2d176446a45e4d48f9bab841a8fe56f11f5a2394a1de829e08fa7534f5eab794'),Point('8598d5a559d1d4492a42c8151a0ba6e8502793f9da7d30d04fe466a0c77d4086'),Point('e37743bae7f5ad5653d5e866ab37ef421d55dfab456d9cc2eab7c8f6bbb2f598'),Point('816c56a6cd630917efcbcf42a4585bfaed75015c13f90915ee9d7ace6ea22196'),Point('cfe2614db372bb5dff6e9811c6d055a242784a8dd48d6abcf25f377853ada97f'),Point('4445632f27b43cdb361c492800230dcfca16a8bbbd78ab001a61f3c7b7f83ef1'),Point('c6da1adfe0973f9511baafbb6fec4339901b9f08927d1970880fc7a662caaeae'),Point('2d829c3ab83eebb41641e81070af4977778a02e26173528ca3e833dfeaa5fd2a'),Point('aa97a8d4aa48cee8f585813d60a97efc55985108c4b77520c9b69a1b1ad04e85'),Point('a33569373f5a50e1c93c6baee9f600fcb6106469f31c04369919397837fa4743'),Point('bbd0e1b516ba9c9b24d3e1b5a71d061848da58213b5c14c5fa655c869095c3c4'),Point('b00bf895382f879300a7779791539e2c7862fec984fb30501125f46f29381e5a'),Point('ed2e6a18dfc1d6024a75c4edb1968839c26d32cccdf233356c6b6a7ff0a47dd9'),Point('096dc77c4aad66917993bf55c53b92e9e4e477a54e8d02605072ba9a22d65821'),Point('8af0dab9e092568c3832dfea2be61eb02ad3c984338407aabf8c69bbfacf558b'),Point('220abdc1086ef49c27528be0173562abc69e8b29ab832ed7a12004f16e392ec2'),Point('b72b0bb174d3367d45e777ea512e4e88ac97ecffc1c1f3be43449a811d0dc719'),Point('451762c1aa0f65e545c25f2542bc66d8839945c56f10647339fd2262956272a8'),Point('9b56499984be2215f21b69f66da856ad07cca328fa21a738cea8f1b720e9fbca'),Point('b14de11fc2679cd80bf60ce111e1d11f8253aed524fc1363748d1eefa902dff7'),Point('e7492d16bf140108f25e22d6cebbe2fd41fb6a457b497aa0f9a294bc7329f779'),Point('c03c23364c18ae9543686b02d7a71c5c714069fdb50706488e0cea1291f4b1e4'),Point('97dc3baad97aba1daf5b731fdf4462633da810dd23910b8b7d7202e2c44d2384'),Point('57f8fcb0a9ee937aa7232c847d3e5a309053a4b5c8ab13870c983808ce047f18'),Point('ecf6940c79ef5cb8dcd729e56a581853279c88b40a138329253808a48e3e2126'),Point('4ce2dc8c90454e9647271d26c7a3432bacf724441cd005e59f20f23cec5b5c49'),Point('f3d78af28737711767f15feb6797e48b59803c5b88dae3566da4c8ca7895e489'),Point('7b055fd807458510082d84ccc2a87ffa7bd4a0e477a358fd7a50e565c68f413a'),Point('5be7111548f32b5c6491620b182dd14ea206e5ec1f80a39e05d1315ffe23148e'),Point('482054905f125fb322b2c9b3cae0e0a476857e6612e8f1f0270e71b042922de1'),Point('99de2c3363df6580be8e42c2b0b499a24b07f7c527844dd038a4c2acd305a1a0'),Point('9a20c0fa618e90471b2fb1e9a7acbe95fc61cc823804e176a5888feec7e0840b'),Point('1eff8019c8468ef4536661ff1d6ff267a43951f7b6f615cc681660108c3ec7ad'),Point('3d61d2beda2071fb8bb8ca723fdfc0a7deee7e350bae7ea57635133f9b00f415'),Point('12cdafb4c93b13cbe155a72a189480f28767dbacc6ac509d29229986fad753d4'),Point('6e123de83280a900d9479fc728059a0090a0b3f691e52497d5b6a7aa8a105e42'),Point('957fdf381d884607b46e1e4bbb59a9c59ac664f35d6e20038d3514830a50a55a'),Point('4ba30efa3ae4312a7ad4b31f0377d10068d035d18b7293dd0151794ebd3d03a1'),Point('d589778991acb83bdb4e1f3f475d009f3422c12be06122e38ee8295883ea519e'),Point('7977c086e3fd1b60e9adda0a08c44c37459fba8c04b83864ee9f4de2eadbc091'),Point('62d696c6dd0fd5f9ef59c822138f72d0e8f0deba819c212531192223a07e25c2'),Point('94a40baf738de9949f353ec4b261283dfd4a4e82221fcbfe10e7e9f4f95f3038'),Point('939fa97d836dfd629bc2ea996cef0b6d11b10489929927005ba42f5ad6d08940'),Point('b3949629fa3e7dbb63f2fae0fc526e7336bdce651a4661a02069043ca4db13af'),Point('fb317da19df1e17ec9defed2f0650554c4b4f9f7027e155e3a7cde120e33e8c9'),Point('bf9adea2748df1aa9408b602fe2e399a9f544d457d43c5a5915fb71be1c49a06'),Point('36ab6ea200178668aa8116bd1f55d306d55679358b624ba36e13ad80466f9596'),Point('8e496cbcebc0c8bd0dca123be547d3399921dfb6ff50849f55b043fe3ef729f1')])
# CiH = PointVector([Point('1c4fa29382ffda9cedbce619818953eae271508d0395e34a5914f268c3aae746'),Point('52fa6842b0b30ac501ba923c3bf2c645b858a2663385cb9906c9ce2f1ad74bcf'),Point('cebdc1399a5d4b96c19e8d2b1f9551e02ba77ba7f209aef98a5d5d48b921ab7f'),Point('1ed057f1e343bb0e14fec57439dbab915b3773fa75edd03b7720660e927be6dd'),Point('4aaff4771af57a6d4db143a9f88d510ebacb73e2795aa44c8505cf0ec4eb4e88'),Point('e3be67ced77bd0e4e05c1dda361b881f274e53fde5dacdd882dc4e6e3c9aaba3'),Point('0e696cef384d90304792c3dad219a7c5efd394316c52bb7ac4df4b5cf71ed34c'),Point('cbd5154fb97f46e6aff3031bb3b52e24b54bcf87b83835c8de0df34ebafeadc6'),Point('a14f040b8b481f4c1212456f804292da7c36e9e7d6218287790caedb8a337a73'),Point('a425548389ae0f7783653d650aa60558bd25a29731dbb58dd74fa50e468e7ad1'),Point('11a4d85f31f3744b3482d57f4c1c4f27ca926a54bb19e98dfc2ed6232acb64ea'),Point('253eb26ad06f04d7e237744eb2e4ab190074b5d32a26996915bb658896f9e5e5'),Point('0a4a5e78c05f55d628e0e9135df91ea4fe2f55bc282b1a9325a93e55ac354581'),Point('50281c92bc95950e64b6d557c347897cfb1f8c0343cddce9806d36dfead21799'),Point('83317a5f89eff8bcf96ccabfddb168ce9e76f1f5be9b10c43b1ca9b5a6a3a2f3'),Point('e4ca55055e7c2c94963b389b598c4868c8d4e78511620b3e01a91a083ba6a24a'),Point('a9ba6b070ced39e918465b185ade582ef07bd0e2781419620498932882386770'),Point('a9c292d5c4fc9116e0352c07fcf69bd285c1448c3b81e77b2e8c293ca70d63a4'),Point('ca76af5e4c65326fb57a816b60adf9201cdbf6a62bc0ba987583371c9156cac3'),Point('b0db11a7be6a244c39da5f82a147ad3ef6878726c6e88e4c34f8ebf679ec916f'),Point('1395df1267916b4a4d08b2203ac0117a1565e12c894aef6209902f392be568d6'),Point('ad538a6685c6447ab1e4b12156e62815b17a0e095e4dfaf79c34a1c5dd941889'),Point('e1d428e82f8fde3b0d0be55e0c4f5b68274d1e909ea5845d5a13f078956c2d84'),Point('5d3376a92acf4f11864d1f847f14814d2be2339912a69435dbed464f9297962d'),Point('12ec63d108b52b8fc0a33a01acf2003ad40a60bbee1b6b3da93700a2af7d1bc4'),Point('d10048871cfe14f6e779deb60ae373d2bf5c4074ec3d562928183d6fdc98218c'),Point('4abd9a88be5672fa15b33458702d3c0df3ae93915175105517e16feb2415eb03'),Point('7418e7a8b5a762a432ff75d1b5c01712d7ba1dd8f055dd4be9bd0bc9da0cbf89'),Point('2deeb51bf1a873cae155a414a067b325deb5b4313e744fc67796888d3af986d8'),Point('46496bce75ab92a3c32d59b99181af100a0925b589ff6812167ba1cd4693900c'),Point('acf5b98ad3b3e7750a7f7a2c02104e2109c8646d08319fad11c6b2eb78e2055e'),Point('b7744076966aa42b38b42d97337b8c458c0131befc93eed150d26c73f288fbfe'),Point('ba854ca543e95000a96b58c7a34a010fae76fca25ba78639e1ded38bae298a54'),Point('1fa1c7d7290b0b555368bb8b57d959046bce41b849c3a444c91f124d4030f538'),Point('749463269d70ebb0460c1f088c89e5df358923b9ad6e82ec4132887e34f4077c'),Point('f74b3c22e7044bcd64d3bfc0aefd8ca1de2886f9f3050cd57b1afa92832643a1'),Point('5f211f5963d71b1aacb8c8c6a7e74a3750f8f79cf61e00ed95c3855de0151882'),Point('1f4aef366e14f10ace57fdadf45f0f5eea87af258c1dc5a185827bf170c17adc'),Point('67c190ae7543047cf52ed177d2e8e9ccb0c10ee519f0884813c9d96a7342c1b9'),Point('ddba136d26ebdb5d971b83f28ea2e5cb36ba6e3b5cfb9b0812dbb6274aa28afc'),Point('3858c78ab835bfa9cfba8fb6c7f71035c5a92976022a3833693ca1dc2814f276'),Point('25a040102b9692981fb703395fa2d6fcced83e30ac31df4a8138ee43a884a5fc'),Point('c108019bcbfda2e1f67b94f4a5580e7b54accd65967610eb7b31420b318bc9c8'),Point('f7ed068e884e534dbe251749f17a35d98c0953b311767d22b8b9a199bce25ccf'),Point('0c7920e77b727edc7232d965ea6839dba3ab4baa202924486a2ef84ac61d26a3'),Point('87d4a1ed3027fd571b1073325325f271d2576fa3ac3a168c31a092467a907241'),Point('6ea92dc4f66571426dc9ce8d2208aa13383f8743779436e92d0c2aab81c3015f'),Point('d698ffe7ea919e81c8dd476f3eee6775e0b36c9cc74231aa1b00067f74391a9f'),Point('18e6e8473013cb1c3d5eda73156ac0898cee8488085cfefceb5ebad6b043ce8b'),Point('bce6a426e7904964362b8efc5fb9b0e5c51e1e9f85f59add275c7a23aee6cce4'),Point('f61340ffd289cc91c0ab4535fbc43ce9fb08f1d6e61ca2e485911f1a7e9c5974'),Point('959b67b1412e1e7a3b8c3af6499b2a213fafd783b26521a04a896f05a189796e'),Point('b91ff4ecce8c095609a8453fc575dcb45e12451ef94cfbc58668b1aa4a56fa01'),Point('c10761b2a56a5093cd1e5a285107ef52bc5bf8f30b4c2ab20274cff6232386b7'),Point('de42b489ca3a3c453212a16d25d7d84e82d30330fdbe3ab49457242418b14247'),Point('9389476fe2c3d10933256063b6b5d8e773833b19e4b5e8261651faaf1d9ccc88'),Point('8a6d3d4e0ee80abc5d656228aa2353028a406a42256c4832abec9b8244766202'),Point('ae1747955870176075c410c3171a41f0435bf7ede553cf961260924417b43f36'),Point('3def4f89efcd41740392d577ede12852c82b2f5d6bc67a302b90d865779f130b'),Point('f3b0c77dd27bed9272a64117cc30fb78f282a4f49f931c13ae90bf67b3937de4'),Point('442a5f488d48fba50e76e69db675219250beb80b7cefe663d3274c7a4c2a055c'),Point('aa817e312bf2d5000da8553369284f0923b07630b014df21d453dce3d3b47ab8'),Point('de4a1d2dfa84b8b6a1d228672f989101764902396ac2503f69a38c98c2220480'),Point('48df54f63dba4216dc6783f8e2abeb17ffdb7dcc973bbf797213707012d407e9')])
# b = '0110100101111110010001100011110100111100101110000000000000000000'

# bbee,bbs0,bbs1 = generate_Borromean(ai,Ci,CiH,b)

# ver,str_out = check_Borromean(Ci,CiH,bbee,bbs0,bbs1)
# print(str_out)
