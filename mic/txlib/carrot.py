"""
MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments
This project incorporates [monero-oxide](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

Carrot addressing primitives by Jeffro.

Implements exactly what's needed to scan a wallet-owned enote and to create enotes:
  - Carrot keyed Blake2b hashes + fixed transcript
  - custom x25519 ladder (mx25519 clamp: clears bits 0-2 and 255, NOT setting 254)
  - FCMP++ generators T, U, V via the unbiased elligator2 double-map (Point::hash)
  - input_context, shared secret, contextualized secret, view tag,
    sender extensions k_g^o / k_t^o, amount blinding, amount enc mask, onetime addr

References: carrot_core/{hash_functions,enote_utils,config,transcript_fixed}.{h,cpp},
            monero-oxide (elligator2),
            external/mx25519 (clamping).
"""



import hashlib

import nacl.bindings
from mic.common import df25519
from mic.common.df25519 import Scalar, Point

P25519 = 2**255 - 19
L = df25519.l
A_MONT = 486662
D_ED = (-121665 * pow(121666, P25519 - 2, P25519)) % P25519

PERSON = b"Monero"  # CARROT_PERSONAL_STRING

# domain separators (config.h)
DS_AMOUNT_BLINDING = b"Carrot commitment mask"
DS_EXT_G = b"Carrot key extension G"
DS_EXT_T = b"Carrot key extension T"
DS_EXT_G_COINBASE = b"Carrot coinbase extension G"
DS_EXT_T_COINBASE = b"Carrot coinbase extension T"
DS_ENC_MASK_ANCHOR = b"Carrot encryption mask anchor"
DS_ENC_MASK_AMOUNT = b"Carrot encryption mask a"
DS_ENC_MASK_PID = b"Carrot encryption mask pid"
DS_JANUS_SPECIAL = b"Carrot janus anchor special"
DS_EPHEMERAL_PRIVKEY = b"Carrot sending key normal"
DS_VIEW_TAG = b"Carrot view tag"
DS_SENDER_RECEIVER = b"Carrot sender-receiver secret"
IC_COINBASE = 0x43  # 'C'
IC_RINGCT = 0x52  # 'R'

ENOTE_TYPE_PAYMENT = 0
ENOTE_TYPE_CHANGE = 1


# --------------------------------------------------------------------------- #
#  field helpers
# --------------------------------------------------------------------------- #
def _inv(x):
    return pow(x, P25519 - 2, P25519)


def _is_qr(v):
    if v % P25519 == 0:
        return True
    return pow(v % P25519, (P25519 - 1) // 2, P25519) == 1


# --------------------------------------------------------------------------- #
#  Carrot Blake2b hash functions   H_x[k](data)
# --------------------------------------------------------------------------- #
def _hash(data: bytes, out_len: int, key: bytes = None) -> bytes:
    kw = {} if key is None else {"key": key}
    h = hashlib.blake2b(data, digest_size=out_len, person=PERSON, **kw)
    return h.digest()


def derive_bytes(data: bytes, out_len: int, key: bytes = None) -> bytes:
    return _hash(data, out_len, key)


def derive_scalar(data: bytes, key: bytes = None) -> Scalar:
    # H_n: blake2b-64 then sc_reduce mod l
    wide = _hash(data, 64, key)
    return Scalar(nacl.bindings.crypto_core_ed25519_scalar_reduce(wide))


def transcript(domain_sep: bytes, *parts: bytes) -> bytes:
    # [1-byte len][domain_sep][parts...]
    assert len(domain_sep) < 256
    out = bytearray([len(domain_sep)])
    out += domain_sep
    for p in parts:
        out += p
    return bytes(out)


# --------------------------------------------------------------------------- #
#  custom x25519 (mx25519 clamp: clear bits 0,1,2 and 255, but do NOT set 254)
# --------------------------------------------------------------------------- #
def _x25519_ladder(k_int: int, u_int: int) -> int:
    a24 = (A_MONT - 2) // 4  # 121665
    x1 = u_int % P25519
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A_ = (x2 + z2) % P25519
        AA = (A_ * A_) % P25519
        B_ = (x2 - z2) % P25519
        BB = (B_ * B_) % P25519
        E = (AA - BB) % P25519
        C_ = (x3 + z3) % P25519
        D_ = (x3 - z3) % P25519
        DA = (D_ * A_) % P25519
        CB = (C_ * B_) % P25519
        x3 = pow((DA + CB) % P25519, 2, P25519)
        z3 = (x1 * pow((DA - CB) % P25519, 2, P25519)) % P25519
        x2 = (AA * BB) % P25519
        z2 = (E * ((AA + a24 * E) % P25519)) % P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * _inv(z2)) % P25519


def x25519_scmul(scalar32: bytes, u32: bytes) -> bytes:
    # mx25519_scmul_key uses the scalar RAW (no RFC/bit clamping). Only the
    # u-coordinate's high bit is masked. Verified against a real on-chain enote.
    k = int.from_bytes(scalar32, "little")
    u = int.from_bytes(u32, "little") & ((1 << 255) - 1)
    return _x25519_ladder(k, u).to_bytes(32, "little")


def x25519_scmul_fast(scalar32: bytes, u32: bytes) -> bytes:
    """C-accelerated equivalent of :func:x25519_scmul, for the scan hot path.

    The pure-Python Montgomery ladder above costs ~1.3 ms/call, dominant when
    scanning millions of blocks.  libsodium has a C scalar mult but the standard
    x25519 entry clamps the scalar, which mx25519 does not.  ed25519_noclamp
    is unclamped, so we lift the Montgomery u to an Edwards point, multiply there,
    and project back:

        u --(birational)--> Edwards y --[k·P in C]--> y' --> u'

    The output u is independent of the sign chosen for the lift (±P share a u, and
    k·(−P) = −(k·P) shares a u with k·P), so the result matches x25519_scmul exactly.
    libsodium rejects low-order / off-curve inputs (raising), and any other edge case
    falls back to the ladder 
    """
    try:
        u = int.from_bytes(u32, "little") & ((1 << 255) - 1)
        y = ((u - 1) * _inv((u + 1) % P25519)) % P25519  # Montgomery u -> Edwards y
        R = nacl.bindings.crypto_scalarmult_ed25519_noclamp(scalar32, y.to_bytes(32, "little"))
        yr = int.from_bytes(R, "little") & ((1 << 255) - 1)
        u2 = (((1 + yr) % P25519) * _inv((1 - yr) % P25519)) % P25519  # Edwards y -> Montgomery u
        return u2.to_bytes(32, "little")
    except Exception:
        return x25519_scmul(scalar32, u32)


# --------------------------------------------------------------------------- #
#  elligator2 hash-to-point (for generators T,U,V): monero-oxide Point::hash
# --------------------------------------------------------------------------- #
def _mul8_point(comp_bytes: bytes) -> Point:
    p = Point(comp_bytes)
    p2 = p + p
    p4 = p2 + p2
    return p4 + p4


def _elligator2(b32: bytes) -> Point:
    r = int.from_bytes(b32, "little") % P25519
    r2 = (r * r) % P25519
    ur2 = (2 * r2) % P25519
    denom = (1 + ur2) % P25519
    upsilon = ((-A_MONT) * _inv(denom)) % P25519
    other = ((-upsilon) - A_MONT) % P25519
    val = (((upsilon + A_MONT) * (upsilon * upsilon % P25519)) + upsilon) % P25519
    eps = _is_qr(val)
    u = upsilon if eps else other
    # Montgomery u -> Edwards y = (u-1)/(u+1)
    y = ((u - 1) * _inv((u + 1) % P25519)) % P25519
    sign = 1 if eps else 0
    comp = bytearray(y.to_bytes(32, "little"))
    comp[31] |= sign << 7
    return _mul8_point(bytes(comp))


def hash_to_point_unbiased(b32: bytes) -> Point:
    wide = hashlib.blake2b(b32, digest_size=64).digest()
    return _elligator2(wide[:32]) + _elligator2(wide[32:])


def _keccak256(b: bytes) -> bytes:
    from Crypto.Hash import keccak

    k = keccak.new(digest_bits=256)
    k.update(b)
    return k.digest()


def hash_to_point_biased(b32: bytes) -> Point:
    # parity with Monero hash_to_ec (== df25519.hash_to_point)
    return _elligator2(_keccak256(b32))


# FCMP++ generators (consensus)
T = hash_to_point_unbiased(_keccak256(b"Monero Generator T"))
U = hash_to_point_unbiased(_keccak256(b"Monero FCMP++ Generator U"))
V = hash_to_point_unbiased(_keccak256(b"Monero FCMP++ Generator V"))


# --------------------------------------------------------------------------- #
#  Carrot derivations
# --------------------------------------------------------------------------- #
def input_context_ringct(first_key_image: bytes) -> bytes:
    if len(first_key_image) != 32:
        raise ValueError(f"key image must be 32 bytes, got {len(first_key_image)}")
    return bytes([IC_RINGCT]) + first_key_image


def input_context_coinbase(block_index: int) -> bytes:
    return bytes([IC_COINBASE]) + block_index.to_bytes(8, "little") + b"\x00" * 24


def shared_secret_receiver(k_view_sec: bytes, d_e_x25519: bytes) -> bytes:
    # s_sr = k_v D_e  (x25519, mx25519 clamp).  Uses the C-accelerated scalar mult:
    # this runs once per output while scanning, so it is the scan's hot path.
    return x25519_scmul_fast(k_view_sec, d_e_x25519)


def contextualized_secret(s_sr: bytes, d_e_x25519: bytes, input_context: bytes) -> bytes:
    t = transcript(DS_SENDER_RECEIVER, d_e_x25519, input_context)
    return derive_bytes(t, 32, key=s_sr)


def view_tag(s_sr: bytes, input_context: bytes, onetime_address: bytes) -> bytes:
    t = transcript(DS_VIEW_TAG, input_context, onetime_address)
    return derive_bytes(t, 3, key=s_sr)


def sender_extension_g(s_ctx: bytes, amount_commitment: bytes) -> Scalar:
    return derive_scalar(transcript(DS_EXT_G, amount_commitment), key=s_ctx)


def sender_extension_t(s_ctx: bytes, amount_commitment: bytes) -> Scalar:
    return derive_scalar(transcript(DS_EXT_T, amount_commitment), key=s_ctx)


def amount_blinding_factor(
    s_ctx: bytes, amount: int, address_spend_pub: bytes, enote_type: int
) -> Scalar:
    t = transcript(
        DS_AMOUNT_BLINDING, amount.to_bytes(8, "little"), address_spend_pub, bytes([enote_type])
    )
    return derive_scalar(t, key=s_ctx)


def amount_encryption_mask(s_ctx: bytes, onetime_address: bytes) -> bytes:
    return derive_bytes(transcript(DS_ENC_MASK_AMOUNT, onetime_address), 8, key=s_ctx)


def onetime_address(address_spend_pub: bytes, s_ctx: bytes, amount_commitment: bytes) -> Point:
    kg = sender_extension_g(s_ctx, amount_commitment)
    kt = sender_extension_t(s_ctx, amount_commitment)
    return Point(address_spend_pub) + (df25519.G * kg) + (T * kt)


# --------------------------------------------------------------------------- #
#  Carrot SENDER primitives (output creation)
# --------------------------------------------------------------------------- #
def convert_point_e(ed_bytes: bytes) -> bytes:
    """ConvertPointE: ed25519 point -> x25519 u-coordinate = (1+y)/(1-y)."""
    y = int.from_bytes(ed_bytes, "little") & ((1 << 255) - 1)
    u = ((1 + y) * _inv((1 - y) % P25519)) % P25519
    return u.to_bytes(32, "little")


def x25519_base(scalar32: bytes) -> bytes:
    """mx25519_scmul_base: x25519 scalar mult of the base point (u=9), raw scalar."""
    k = int.from_bytes(scalar32, "little")
    return _x25519_ladder(k, 9).to_bytes(32, "little")


def shared_secret_sender(d_e: bytes, address_view_pub: bytes) -> bytes:
    # s_sr = d_e * ConvertPointE(K^j_v)
    return x25519_scmul(d_e, convert_point_e(address_view_pub))


def enote_ephemeral_privkey(
    anchor16: bytes, input_context: bytes, address_spend_pub: bytes, payment_id8: bytes
) -> Scalar:
    t = transcript(DS_EPHEMERAL_PRIVKEY, anchor16, input_context, address_spend_pub, payment_id8)
    return derive_scalar(t)  # unkeyed


def anchor_encryption_mask(s_ctx: bytes, onetime_address: bytes) -> bytes:
    return derive_bytes(transcript(DS_ENC_MASK_ANCHOR, onetime_address), 16, key=s_ctx)


def _selftest_fast_x25519() -> None:
    """Fail loudly at import if the C scalar mult disagrees with the ladder.

    Guards against a broken/mismatched libsodium so scanning can never silently use
    a wrong ECDH.  One ladder + one fast call on a fixed vector: negligible cost.
    """
    k = (7).to_bytes(32, "little")
    u = x25519_base((3).to_bytes(32, "little"))
    if x25519_scmul_fast(k, u) != x25519_scmul(k, u):
        raise RuntimeError(
            "carrot.x25519_scmul_fast disagrees with the reference ladder: "
            "libsodium ed25519_noclamp is unavailable or broken"
        )


_selftest_fast_x25519()


if __name__ == "__main__":
    print("T =", T)
    print("U =", U)
    print("V =", V)
    print("G =", df25519.G)
    print("H =", df25519.H)
