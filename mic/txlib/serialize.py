"""
MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments
This project incorporates [monero-oxide](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

FCMP++ transaction (de)serializer.

Implements the exact byte layout used by the fcmp++-beta-stressnet build for a
version-2, rct type 7 (RCTTypeFcmpPlusPlus) transaction with Carrot v1 outputs.

Reference (fcmp++-stressnet/monero-gui-repo/monero/src):
  cryptonote_basic/cryptonote_basic.h    prefix, txin_to_key(0x2), txout_to_carrot_v1(0x0)
  ringct/rctTypes.h                      rctSigBase + rctSigPrunable (type 7)

Layout
------
prefix:
  varint version (=2)
  varint unlock_time
  vin:  varint n, each = 0x02 | varint amount | varint n_offsets | n*varint | 32 k_image
  vout: varint n, each = varint amount | 0x00 | 32 key | 3 view_tag | 16 janus_anchor
  extra: varint len | bytes
rct base (type 7):
  1 byte type (=7)
  varint txnFee
  ecdhInfo: outputs * 8 bytes (truncated encrypted amount)
  outPk:    outputs * 32 bytes (commitment mask == the output commitment)
rct prunable (type 7):
  varint nbp
  bpp[nbp]: each A,A1,B,r1,s1,d1 (32 each) | varint Ln,L[..] | varint Rn,R[..]
  varint reference_block
  1 byte n_tree_layers
  fcmp_pp blob (fcmp_pp_proof_len(inputs, n_tree_layers) bytes, no prefix)
  pseudoOuts: inputs * 32 bytes (no prefix)
"""



from dataclasses import dataclass, field
from typing import List


# --------------------------------------------------------------------------- #
#  varint + cursor helpers
# --------------------------------------------------------------------------- #
def write_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def varint(self) -> int:
        shift = 0
        res = 0
        while True:
            b = self.d[self.i]
            self.i += 1
            res |= (b & 0x7F) << shift
            if not (b & 0x80):
                return res
            shift += 7

    def take(self, n: int) -> bytes:
        b = self.d[self.i : self.i + n]
        if len(b) != n:
            raise EOFError(f"need {n} bytes, have {len(b)} at offset {self.i}")
        self.i += n
        return b

    def byte(self) -> int:
        return self.take(1)[0]

    def remaining(self) -> int:
        return len(self.d) - self.i


class Writer:
    def __init__(self):
        self.parts: List[bytes] = []

    def varint(self, n: int):
        self.parts.append(write_varint(n))

    def raw(self, b: bytes):
        self.parts.append(b)

    def byte(self, n: int):
        self.parts.append(bytes([n]))

    def out(self) -> bytes:
        return b"".join(self.parts)


# --------------------------------------------------------------------------- #
#  FCMP++ proof length
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  data classes
# --------------------------------------------------------------------------- #
@dataclass
class TxIn:
    amount: int
    key_offsets: List[int]
    k_image: bytes  # 32


@dataclass
class CarrotOut:
    amount: int
    key: bytes  # 32
    view_tag: bytes  # 3
    encrypted_janus_anchor: bytes  # 16


@dataclass
class BulletproofPlus:
    A: bytes
    A1: bytes
    B: bytes
    r1: bytes
    s1: bytes
    d1: bytes
    L: List[bytes]
    R: List[bytes]


@dataclass
class Transaction:
    version: int = 2
    unlock_time: int = 0
    vin: List[TxIn] = field(default_factory=list)
    vout: List[CarrotOut] = field(default_factory=list)
    extra: bytes = b""
    # rct base
    rct_type: int = 7
    txnFee: int = 0
    ecdhInfo: List[bytes] = field(default_factory=list)  # 8 bytes each
    outPk: List[bytes] = field(default_factory=list)  # 32 bytes each
    # rct prunable
    bpp: List[BulletproofPlus] = field(default_factory=list)
    reference_block: int = 0
    n_tree_layers: int = 0
    fcmp_pp: bytes = b""
    pseudoOuts: List[bytes] = field(default_factory=list)  # 32 bytes each

    @property
    def n_inputs(self) -> int:
        return len(self.vin)

    @property
    def n_outputs(self) -> int:
        return len(self.vout)


# --------------------------------------------------------------------------- #
#  parse
# --------------------------------------------------------------------------- #
def parse_tx(blob: bytes) -> Transaction:
    r = Reader(blob)
    tx = Transaction()
    tx.version = r.varint()
    tx.unlock_time = r.varint()

    n_vin = r.varint()
    for _ in range(n_vin):
        t = r.byte()
        if t != 0x02:
            raise ValueError(f"unsupported vin tag 0x{t:02x} (expected txin_to_key 0x02)")
        amount = r.varint()
        n_off = r.varint()
        offs = [r.varint() for _ in range(n_off)]
        ki = r.take(32)
        tx.vin.append(TxIn(amount, offs, ki))

    n_vout = r.varint()
    for _ in range(n_vout):
        amount = r.varint()
        t = r.byte()
        if t != 0x00:
            raise ValueError(f"unsupported vout tag 0x{t:02x} (expected carrot_v1 0x00)")
        key = r.take(32)
        vt = r.take(3)
        anchor = r.take(16)
        tx.vout.append(CarrotOut(amount, key, vt, anchor))

    extra_len = r.varint()
    tx.extra = r.take(extra_len)

    if tx.version < 2:
        return tx

    # rct base
    tx.rct_type = r.byte()
    if tx.rct_type == 0:
        return tx
    tx.txnFee = r.varint()
    nout = len(tx.vout)
    tx.ecdhInfo = [r.take(8) for _ in range(nout)]
    tx.outPk = [r.take(32) for _ in range(nout)]

    # rct prunable
    if tx.rct_type != 7:
        raise ValueError(f"only rct type 7 (FCMP++) supported, got {tx.rct_type}")
    nbp = r.varint()
    for _ in range(nbp):
        A, A1, B, r1, s1, d1 = (r.take(32) for _ in range(6))
        nL = r.varint()
        L = [r.take(32) for _ in range(nL)]
        nR = r.varint()
        R = [r.take(32) for _ in range(nR)]
        tx.bpp.append(BulletproofPlus(A, A1, B, r1, s1, d1, L, R))
    tx.reference_block = r.varint()
    tx.n_tree_layers = r.byte()
    inputs = len(tx.vin)
    # fcmp_pp blob has no length prefix.  Infer it from what remains minus the
    # trailing pseudoOuts (inputs * 32).  Cross-check against the formula.
    fcmp_len = r.remaining() - inputs * 32
    if fcmp_len < 0:
        raise ValueError("buffer too short for fcmp_pp + pseudoOuts")
    tx.fcmp_pp = r.take(fcmp_len)
    tx.pseudoOuts = [r.take(32) for _ in range(inputs)]
    if r.remaining() != 0:
        raise ValueError(f"{r.remaining()} trailing bytes after parse")
    return tx


# --------------------------------------------------------------------------- #
#  serialize
# --------------------------------------------------------------------------- #
def serialize_prefix(tx: Transaction) -> bytes:
    w = Writer()
    w.varint(tx.version)
    w.varint(tx.unlock_time)
    w.varint(len(tx.vin))
    for vin in tx.vin:
        w.byte(0x02)
        w.varint(vin.amount)
        w.varint(len(vin.key_offsets))
        for o in vin.key_offsets:
            w.varint(o)
        w.raw(vin.k_image)
    w.varint(len(tx.vout))
    for o in tx.vout:
        w.varint(o.amount)
        w.byte(0x00)
        w.raw(o.key)
        w.raw(o.view_tag)
        w.raw(o.encrypted_janus_anchor)
    w.varint(len(tx.extra))
    w.raw(tx.extra)
    return w.out()


def _fixed(b: bytes, n: int, what: str) -> None:
    """Reject a wrong-length field. A raise, not an assert: python -O keeps it."""
    if len(b) != n:
        raise ValueError(f"{what} must be {n} bytes, got {len(b)}")


def serialize_rct_base(tx: Transaction) -> bytes:
    w = Writer()
    w.byte(tx.rct_type)
    if tx.rct_type == 0:
        return w.out()
    w.varint(tx.txnFee)
    for e in tx.ecdhInfo:
        _fixed(e, 8, "ecdhInfo")
        w.raw(e)
    for c in tx.outPk:
        _fixed(c, 32, "outPk")
        w.raw(c)
    return w.out()


def serialize_rct_prunable(tx: Transaction) -> bytes:
    w = Writer()
    w.varint(len(tx.bpp))
    for bp in tx.bpp:
        for x in (bp.A, bp.A1, bp.B, bp.r1, bp.s1, bp.d1):
            _fixed(x, 32, "bulletproof element")
            w.raw(x)
        w.varint(len(bp.L))
        for x in bp.L:
            w.raw(x)
        w.varint(len(bp.R))
        for x in bp.R:
            w.raw(x)
    w.varint(tx.reference_block)
    w.byte(tx.n_tree_layers)
    w.raw(tx.fcmp_pp)
    for p in tx.pseudoOuts:
        _fixed(p, 32, "pseudoOuts")
        w.raw(p)
    return w.out()


def serialize_tx(tx: Transaction) -> bytes:
    out = serialize_prefix(tx)
    if tx.version >= 2:
        out += serialize_rct_base(tx)
        if tx.rct_type != 0:
            out += serialize_rct_prunable(tx)
    return out
