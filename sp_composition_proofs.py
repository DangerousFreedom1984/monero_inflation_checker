import dumber25519
from dumber25519 import Scalar, Point, PointVector, ScalarVector,hash_to_point,hash_to_scalar,random_scalar,cn_fast_hash, sp_hash_to_scalar
import copy
import misc_func
import varint_mic as varint
import pyblake2
import nacl.bindings
import sp_classes 


def compute_challenge_message(message,K,KI,K_t1):
    X = dumber25519.X
    U = dumber25519.U
    label_FS = '\003\rFS_transcript\003\021sp_FS_transcript\000'
    label_separator = 'domain_separator'
    label_decomposition = 'sp_composition_proof_challenge_message'
    label_X = 'X'
    label_U = 'U'
    label_message = 'message'
    label_K = 'K'
    label_KI = 'KI'
    label_Kt1 = 'K_t1'
    ts = sp_classes.transcript(label_FS)
    ts.append_label(label_separator)
    ts.append_label(label_decomposition)
    ts.append_label_value(label_X,str(X))
    ts.append_label_value(label_U,str(U))
    ts.append_label_value(label_message,message)
    ts.append_label_value(label_K,K)
    ts.append_label_value(label_KI,KI)
    ts.append_label_value(label_Kt1,K_t1)
    transcript = ts.get()
    challenge = nacl.bindings.crypto_generichash_blake2b_salt_personal(bytes(transcript)).hex()
    return challenge

def compute_challenge(challenge_message,K_t1_proofkey, K_t2_proofkey, KI_proofkey):
    label_FS = '\003\rFS_transcript\003\021sp_FS_transcript\000'
    label_separator = 'domain_separator'
    label_decomposition = 'sp_composition_proof_challenge'
    label_message = 'challenge_message'
    label_Kt1 = 'K_t1_proofkey'
    label_Kt2 = 'K_t2_proofkey'
    label_KI = 'KI_proofkey'
    ts = sp_classes.transcript(label_FS)
    ts.append_label(label_separator)
    ts.append_label(label_decomposition)
    ts.append_label_value(label_message,challenge_message)
    ts.append_label_value(label_Kt1,K_t1_proofkey)
    ts.append_label_value(label_Kt2,K_t2_proofkey)
    ts.append_label_value(label_KI,KI_proofkey)
    transcript = ts.get()
    challenge = sp_hash_to_scalar(bytes(transcript))
    return challenge


def composition_prove(message,K,x,y,z):

    G = dumber25519.G
    X = dumber25519.X
    U = dumber25519.U
    inv8 = Scalar(8).invert()

    proof = sp_classes.composition_proof()

    if K != x*G+y*X+z*U:
        print('Inputs dont match')
        return

    proof.K_t1 = inv8 * y.invert() * K

    KI = z * y.invert() * U

    alpha_t1 = random_scalar()
    aT1 = alpha_t1 * K

    alpha_t2 = random_scalar()
    aT2 = alpha_t2 * G

    alpha_ki = random_scalar()
    aKI = alpha_ki * U



    m = compute_challenge_message(str(message),str(K),str(KI),str(proof.K_t1))

    proof.c = compute_challenge(str(m), str(aT1), str(aT2), str(aKI))


    proof.r_t1 = alpha_t1 - proof.c * y.invert()
    proof.r_t2 = alpha_t2 - proof.c * x * y.invert()
    proof.r_ki = alpha_ki - proof.c * z * y.invert()

    return proof



def composition_verify(proof, messsage,K,KI):

    G = dumber25519.G
    X = dumber25519.X
    U = dumber25519.U
    inv8 = Scalar(8).invert()
    
    m = compute_challenge_message(str(message),str(K),str(KI),str(proof.K_t1))

    K_t1 = proof.K_t1*Scalar(8)

    K_t2 = K_t1 - X - KI

    K_t1_part = proof.r_t1 * K + proof.c * K_t1

    K_t2_part = proof.r_t2 * G + proof.c * K_t2

    KI_part = proof.r_ki * U + proof.c * KI

    challenge_nom = compute_challenge(str(m),str(K_t1_part),str(K_t2_part),str(KI_part))

    if challenge_nom == proof.c:
        return True

    return False


message = str('6c9c4bb09e9c4023561b211c627502468f3d13bb17d51fff2736f6f5b90b65c8')
K= Point('41d4d040c81afbd66049cb62306a8ab75b66cc84d5220498f918012cb474e276')
x= Scalar('bdf74ce06f6278df771370e35b957e71cb85bf76ef604d3eb81a6ec1c7232509')
y= Scalar('3eb8b5aad5a59bb1e2206476abc780da665c36a1df8d23d3482f2fadba6a5e07')
z= Scalar('69476194bfcda8d33c9b92c05817540f17991812a4a44740866c52925255c003')
KI = z * y.invert() * dumber25519.U

proof = composition_prove(message,K,x,y,z)

ver = composition_verify(proof, message, K, KI)

