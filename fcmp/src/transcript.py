"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

GBP transcript — exact translation of generalized-bulletproofs/src/transcript.rs

Blake2b-512 accumulates all inputs; challenge() clones the state, appends
the CHALLENGE tag, and calls from_uniform_bytes on the 64-byte digest.

Separate from the outer FCMP Blake2b-32 context hash (Fcmp::transcript()).
"""

import hashlib
import copy

from curve import point_to_bytes

SCALAR = 0
POINT = 1
CHALLENGE = 2


class ProverTranscript:
    """Mirrors generalized_bulletproofs::transcript::Transcript."""

    def __init__(self, context: bytes):
        if len(context) != 32:
            raise ValueError(f"transcript context must be 32 bytes, got {len(context)}")
        self._digest = hashlib.blake2b(digest_size=64)
        self._digest.update(context)
        self._buf = bytearray()

    def push_scalar(self, field_element) -> None:
        b = field_element.to_bytes()  # 32 bytes LE
        self._digest.update(bytes([SCALAR]))
        self._digest.update(b)
        self._buf.extend(b)

    def push_point(self, point) -> None:
        b = point_to_bytes(point)  # 32 bytes compressed
        self._digest.update(bytes([POINT]))
        self._digest.update(b)
        self._buf.extend(b)

    def write_commitments(self, C_list: list, V_list: list) -> tuple:
        """Transcript C and V commitment lists; return them unchanged."""
        n_c = len(C_list)
        n_v = len(V_list)
        self._digest.update(n_c.to_bytes(8, "little"))
        for pt in C_list:
            self.push_point(pt)
        self._digest.update(n_v.to_bytes(8, "little"))
        for pt in V_list:
            self.push_point(pt)
        return C_list, V_list

    def challenge(self, field_cls):
        """Sample a challenge in field_cls.  Matches Transcript::challenge::<C>().

        Advance state with [CHALLENGE], then clone+finalize to get the 64-byte hash.
        Each call advances the running digest, so consecutive calls produce different values.
        """
        self._digest.update(bytes([CHALLENGE]))
        h = self._digest.copy().digest()  # 64 bytes
        res = field_cls.from_uniform_bytes(h)
        if res.is_zero():
            raise RuntimeError("zero challenge (negligible probability)")
        return res

    def challenge_bytes(self) -> bytes:
        self._digest.update(bytes([CHALLENGE]))
        return self._digest.copy().digest()

    def complete(self) -> bytes:
        return bytes(self._buf)


class VerifierTranscript:
    """Mirrors generalized_bulletproofs::transcript::VerifierTranscript."""

    def __init__(self, context: bytes, proof: bytes):
        if len(context) != 32:
            raise ValueError(f"transcript context must be 32 bytes, got {len(context)}")
        self._digest = hashlib.blake2b(digest_size=64)
        self._digest.update(context)
        self._proof = bytearray(proof)
        self._pos = 0

    def _read_bytes(self, n: int) -> bytes:
        chunk = bytes(self._proof[self._pos : self._pos + n])
        if len(chunk) < n:
            raise EOFError("not enough bytes in proof")
        self._pos += n
        return chunk

    def read_scalar(self, field_cls):
        self._digest.update(bytes([SCALAR]))
        raw = self._read_bytes(32)
        self._digest.update(raw)
        fe = field_cls.from_bytes(raw)
        if fe is None:
            raise ValueError("non-canonical scalar in proof")
        return fe

    def read_point(self, from_bytes_fn):
        self._digest.update(bytes([POINT]))
        raw = self._read_bytes(32)
        self._digest.update(raw)
        pt = from_bytes_fn(raw)
        if pt is None:
            raise ValueError("invalid point in proof")
        return pt

    def read_commitments(self, n_c: int, n_v: int, from_bytes_fn) -> tuple:
        self._digest.update(n_c.to_bytes(8, "little"))
        C = [self.read_point(from_bytes_fn) for _ in range(n_c)]
        self._digest.update(n_v.to_bytes(8, "little"))
        V = [self.read_point(from_bytes_fn) for _ in range(n_v)]
        return C, V

    def challenge(self, field_cls):
        self._digest.update(bytes([CHALLENGE]))
        h = self._digest.copy().digest()
        res = field_cls.from_uniform_bytes(h)
        if res.is_zero():
            raise RuntimeError("zero challenge (negligible probability)")
        return res

    def challenge_bytes(self) -> bytes:
        self._digest.update(bytes([CHALLENGE]))
        return self._digest.copy().digest()

    def is_exhausted(self) -> bool:
        """Return True if all proof bytes have been consumed."""
        return self._pos == len(self._proof)

    def complete(self) -> bytes:
        return bytes(self._proof[self._pos :])


# ---------------------------------------------------------------------------
# Outer FCMP context hash — Fcmp::transcript() in lib.rs
# Uses Blake2b-32, NOT Blake2b-512, and produces a 32-byte context consumed
# by ProverTranscript / VerifierTranscript.
# ---------------------------------------------------------------------------


def fcmp_transcript_context(tree_root: bytes, inputs, root_blind_R: bytes) -> bytes:
    """Compute the 32-byte context fed into the GBP transcript.

    Mirrors Fcmp::transcript() in fcmps/src/lib.rs.

    tree_root     : 32 bytes (compressed OC point)
    inputs        : list of input dicts with keys 'O' and 'I' (32-byte compressed points each)
    root_blind_R  : 32 bytes

    Returns 32-byte Blake2b-32 digest.
    """
    d = hashlib.blake2b(digest_size=32)
    d.update(tree_root)
    for inp in inputs:
        d.update(inp["O"])  # output key
        d.update(inp["I"])  # input key
    d.update(root_blind_R)
    return d.digest()
