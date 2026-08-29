"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.


End to end: build a real FCMP++ spend offline, then verify it every way we can.

The module first synthesizes a complete and valid
instance of a curve tree, the output being spent and its re-randomization. Then it proves
membership over it, wraps the result in a genuine transaction (rct type 7, Carrot
v1 outputs, real Bulletproof+) and then runs the same verification a that a node would do.

To run it:

    python -m mic.tests.fcmp.test_end_to_end
    python -m mic.tests.fcmp.test_end_to_end --layers 4
    python -m mic.tests.fcmp.test_end_to_end --layers 1,3,6,8 --proof-dir proofs
    python -m unittest mic.tests.fcmp.test_end_to_end
    MIC_FCMP_LAYERS=4 python -m unittest mic.tests.fcmp.test_end_to_end

--layers picks which tree depths get built and defaults to 1,3,6,8. Under
python -m unittest, where unittest owns the arguments, MIC_FCMP_LAYERS says the
same thing.

Every run is deterministic. All the randomness the build reaches for is pinned
to a seed fixed by the depth alone, so a depth always yields the same
transaction down to the byte (see PinnedRandomness). Each depth is then written
out as proofs/fcmp_proof_<n>layers.json in the shape a daemon hands a
transaction out in, so the file is a finished FCMP++ proof as it would sit in a
block: the membership proof, the SAL proof, the Bulletproof+ and the blinded
input tuple, plus the tree root the block commits to.



── the fixture ───────────────────────────────────────────────────────────────

What a fixture holds:

    O, I, C          the output being spent: one-time address, key image base
                     I = Hp(O), and amount commitment
    rr               the re-randomization (r_o, r_i, r_r_i, r_c) and the blinded
                     tuple O~ = O + r_o T, I~ = I + r_i U, R = r_i V + r_r_i T,
                     C~ = C + r_c G. The same scalars bridge the membership proof
                     and the SAL proof (see mic/fcmp/sal.py)
    x                the private key of O (O = x G), needed by the SAL prover.
                     Since the fixture builds O directly from x, y_orig = 0 and
                     the SAL's y is exactly r_o
    tree             the curve tree the membership proof opens

A curve-tree node is a Pedersen vector commitment to its children's x-coordinates,
so a node's own x-coordinate is directly committable by its parent. That is the
whole point of the Helios/Selene 2-cycle:

    Selene point  ->  x in SeleneField = Helios's scalar field  ->  a Helios node
    Helios point  ->  x in HeliosField = Selene's scalar field  ->  a Selene node

    node = hash_init + sum(children_x * g_bold)

The leaf layer commits 38 outputs by 6 coordinates with the C1 generators, giving a
Selene node. Layers then alternate, C2 (Helios, width 18) and C1 (Selene, width
38). Sibling entries are random field elements: a branch is only a committed vector,
and the circuit's member_of_list merely checks the child's x is somewhere in it.
"""

import argparse
import json
import os
import random
import secrets
import shutil
import sys
import tempfile
import unittest

import nacl.utils
from Crypto.Hash import keccak

from mic import paths

from mic.common import df25519
from mic.common.df25519 import Point, Scalar
from mic.fcmp.curve import ED25519_L, WPoint, oc_from_bytes, point_to_bytes
from mic.fcmp.field import HeliosField, SeleneField
from mic.fcmp.gbp import Generators
from mic.fcmp.multiexp import multiexp
from mic.fcmp.proof import (
    Fcmp,
    BranchesWithBlinds,
    PerInputData,
    Output,
    RootBranchLeaves,
    RootBranchC1,
    RootBranchC2,
    LAYER_ONE_LEN,
    LAYER_TWO_LEN,
)
from mic.fcmp import sal as _sal
from mic.rangeproofs import check_rangeproofs
from mic.tools import scan as _scan
from mic.txlib import blinds as _blinds
from mic.txlib import carrot
from mic.txlib import serialize as _serialize

L = ED25519_L

# A layer's values live in one field, which fixes both the width and which curve's
# generators commit them:  HeliosField -> C1 (a Selene node), SeleneField -> C2.
_C1, _C2 = "C1", "C2"

FEE = 600000000  # 0.0006 XMR
PAY = 1000000000  # 0.001 XMR

# Where the synthetic transaction pretends to live, for the replay dump. A block
# at height H carries the curve-tree root for lock index H + 8, and a tx's
# reference_block is a lock index: see scan.LOCK_OFFSET.
DEMO_HEIGHT = 1_000_000


# --------------------------------------------------------------------------- #
#  what this run builds, and why it comes out the same every time
# --------------------------------------------------------------------------- #

DEFAULT_LAYERS = (1, 3, 6, 8)

# The tree depths this run builds. --layers on the command line, or
# MIC_FCMP_LAYERS when unittest owns the arguments, replaces it before any test
# runs, and the tests read it at call time rather than closing over it.
LAYERS = DEFAULT_LAYERS

# Where the blockchain-shaped proof files land.
PROOF_DIR = os.path.join(paths.ROOT, "proofs")


def _parse_layers(text: str) -> tuple:
    """Parse "4" or "1,3,6,8" into a tuple of depths, in the order given."""
    out = []
    for part in text.replace(",", " ").split():
        n = int(part)
        if n < 1:
            raise ValueError(f"a tree has at least its leaf layer, got {n}")
        if n not in out:
            out.append(n)
    if not out:
        raise ValueError("no tree depth given")
    return tuple(out)


if os.environ.get("MIC_FCMP_LAYERS"):
    try:
        LAYERS = _parse_layers(os.environ["MIC_FCMP_LAYERS"])
    except ValueError as e:
        raise SystemExit(f"MIC_FCMP_LAYERS: {e}")
if os.environ.get("MIC_FCMP_PROOF_DIR"):
    PROOF_DIR = os.path.abspath(os.environ["MIC_FCMP_PROOF_DIR"])


def primary() -> int:
    """The depth the depth-independent tests run at, so they build nothing extra."""
    return LAYERS[0]


def seed_for(layers: int) -> int:
    """The single seed a depth gets. Every random draw in its build descends from
    this, which is what makes the proof a function of the depth and nothing else."""
    return 40 + layers


class PinnedRandomness:
    """Replace every OS-randomness source the build reaches for.

    There are four, and missing one leaves the transaction different on every run:

        secrets.token_bytes   the membership proof's blinding factors
        secrets.randbits      the branch blinds
        os.urandom            the Carrot anchors
        nacl.utils.random     what df25519.random_scalar draws on, so the SAL
                              nonces and the Bulletproof+ nonces

    All four are served from one random.Random, so the build is reproducible as a
    whole rather than piecewise: the same seed replays the same draws in the same
    order, provided the build asks for them in the same order, which it does.
    Nesting is safe, since __exit__ restores whatever was in place on entry.
    """

    def __init__(self, seed: int):
        self._rng = random.Random(seed)
        self._saved = {}

    def _bytes(self, n: int) -> bytes:
        return self._rng.getrandbits(8 * n).to_bytes(n, "little")

    def __enter__(self):
        self._saved = {
            "token_bytes": secrets.token_bytes,
            "randbits": secrets.randbits,
            "urandom": os.urandom,
            "nacl_random": nacl.utils.random,
        }
        secrets.token_bytes = lambda n=32: self._bytes(n)
        secrets.randbits = lambda k: self._rng.getrandbits(k)
        os.urandom = lambda n: self._bytes(n)
        nacl.utils.random = lambda n=32: self._bytes(n)
        return self

    def __exit__(self, *exc):
        secrets.token_bytes = self._saved["token_bytes"]
        secrets.randbits = self._saved["randbits"]
        os.urandom = self._saved["urandom"]
        nacl.utils.random = self._saved["nacl_random"]
        return False


# --------------------------------------------------------------------------- #
#  tree construction
# --------------------------------------------------------------------------- #


def hash_layer(params, values: list, side: str):
    """One curve-tree node: hash_init + Σ valuesᵢ · g_boldᵢ.

    The same commitment Fcmp._compute_tree_root forms for the root, which is why
    a tree built this way verifies against it.
    """
    if side == _C1:
        g_bold, hash_init = params.curve_1_generators.g_bold_slice(), params.curve_1_hash_init
    else:
        g_bold, hash_init = params.curve_2_generators.g_bold_slice(), params.curve_2_hash_init
    identity = WPoint.identity(hash_init.field_cls, hash_init.B)
    return hash_init + multiexp(list(zip(values, g_bold[: len(values)])), identity)


class Tree:
    """The synthesized curve tree, and the path from one leaf to the root."""

    def __init__(self, layers, leaves, branches_c1, branches_c2, root, root_point):
        self.layers = layers
        self.leaves = leaves              # the 38 leaf Outputs (None when layers == 1)
        self.branches_c1 = branches_c1    # HeliosField vectors, width 38
        self.branches_c2 = branches_c2    # SeleneField vectors, width 18
        self.root = root                  # RootBranchLeaves | RootBranchC1 | RootBranchC2
        self.root_point = root_point      # the root node, for the self-check

    @property
    def is_c1(self):
        """Odd depths put the root on C1/Selene, even depths on C2/Helios."""
        return (self.layers % 2) == 1


def _random_output(rand):
    """A leaf that is a well-formed (O, I, C) tuple but nobody's actual output."""
    O = (df25519.G * rand()).b
    I = carrot.hash_to_point_unbiased(O).b
    C = (df25519.G * rand()).b
    return Output(oc_from_bytes(O), oc_from_bytes(I), oc_from_bytes(C))


def build_tree(params, output, layers: int, rand) -> "Tree":
    """Synthesize a layers-deep tree containing output, and the path to it.

    Layer 0 is the leaves, and layers 1..L−1 are interior, alternating C2 then C1. The
    topmost interior layer becomes the root branch, and everything below it becomes
    branches_c1 / branches_c2 according to which field its values live in.
    """
    if layers < 1:
        raise ValueError("a tree has at least its leaf layer")

    if layers == 1:
        # The leaf layer is the root: no branches, no branch blinds.
        root = RootBranchLeaves([output])
        return Tree(1, None, [], [], root, None)

    # -- leaves: the spent output among 37 decoys ------------------------
    leaves = [_random_output(rand) for _ in range(LAYER_ONE_LEN)]
    leaves[rand().to_int() % LAYER_ONE_LEN] = output
    leaf_values = []
    for out in leaves:
        leaf_values.extend([out.O[0], out.O[1], out.I[0], out.I[1], out.C[0], out.C[1]])
    node = hash_layer(params, leaf_values, _C1)  # a Selene point

    # -- interior layers: alternate C2 (width 18) and C1 (width 38) -------
    branches_c1, branches_c2 = [], []
    root = root_point = None
    for level in range(1, layers):
        if level % 2 == 1:
            side, F, width = _C2, SeleneField, LAYER_TWO_LEN   # commits Selene x's
        else:
            side, F, width = _C1, HeliosField, LAYER_ONE_LEN   # commits Helios x's

        siblings = [F(rand().to_int() % F.P) for _ in range(width)]
        siblings[rand().to_int() % width] = node.x  # the child on our path
        parent = hash_layer(params, siblings, side)

        if level == layers - 1:
            root = RootBranchC2(siblings) if side == _C2 else RootBranchC1(siblings)
            root_point = parent
        elif side == _C2:
            branches_c2.append(siblings)
        else:
            branches_c1.append(siblings)
        node = parent

    tree = Tree(layers, leaves, branches_c1, branches_c2, root, root_point)
    if 1 + len(branches_c1) + len(branches_c2) + 1 != layers:
        raise ValueError(f"layer bookkeeping: {layers} layers did not come back out")
    return tree


# --------------------------------------------------------------------------- #
#  the fixture
# --------------------------------------------------------------------------- #


class Fixture:
    """A valid FCMP++ instance plus everything needed to prove and verify it."""

    def __init__(self, params, x, O, I, C, rr, tree, amount=None, mask=None, rand=None):
        self.params = params
        self.x = x  # O = x G  (SAL's spend key)
        self.O, self.I, self.C = O, I, C
        self.rr = rr
        self.tree = tree
        self.amount = amount  # set only when C was built as mask·G + amount·H
        self.mask = mask
        self._rand = rand
        self.layers = tree.layers
        self.is_c1 = tree.is_c1
        self.output = Output(oc_from_bytes(O), oc_from_bytes(I), oc_from_bytes(C))

    # -- membership proof inputs -------------------------------------------

    def branches(self):
        """BranchesWithBlinds for this tree, with fresh blinds.

        Blinds carry EC divisors and are drawn per call, so two calls give two
        different (both valid) witnesses for the same statement.
        """
        output_blinds = self.rr.output_blinds()
        tree = self.tree
        b1, b2 = _blinds.build_branch_blinds(self.params, tree.layers, n_inputs=1)
        per_input = PerInputData(
            self.output, output_blinds, tree.branches_c1, tree.branches_c2, tree.leaves
        )
        return BranchesWithBlinds([per_input], tree.root, b1, b2)

    def root_bytes(self, bwb):
        """The tree root, as the verifier receives it.

        Self-check: Fcmp._compute_tree_root derives the root from the root branch
        alone, so agreeing with the node we hashed while building confirms the whole
        layer assignment (which field, which width, which generators) is right.

        Raises rather than asserts, so `python -O` cannot strip the check.
        """
        is_c1, root_bytes, _pt = Fcmp._compute_tree_root(bwb, self.params)
        if is_c1 != self.is_c1:
            raise ValueError(f"root curve mismatch at {self.layers} layers")
        if self.tree.root_point is not None:
            expected = point_to_bytes(self.tree.root_point)
            if root_bytes != expected:
                raise ValueError("computed root disagrees with the built tree")
        return root_bytes

    def verify_inputs(self):
        """The blinded input tuple as the verifier expects it (affine OC coords)."""
        rr = self.rr
        return [
            {
                "O_tilde": oc_from_bytes(rr.O_tilde),
                "I_tilde": oc_from_bytes(rr.I_tilde),
                "R": oc_from_bytes(rr.R),
                "C_tilde": oc_from_bytes(rr.C_tilde),
            }
        ]

    # -- SAL proof inputs ---------------------------------------------------

    def sal_secrets(self):
        """(x, y, r_i, r_r_i) for sal.prove.

        y = r_o + y_orig, and the fixture's O = x G carries no T component, so
        y_orig = 0 and y = r_o.
        """
        rr = self.rr
        return self.x, rr.r_o, rr.r_i, rr.r_r_i


def make_fixture(params=None, seed: int = None, amount: int = None, mask=None,
                 r_c=None, layers: int = 1) -> "Fixture":
    """Synthesize a random valid instance at layers tree depth. No node required.

    seed makes the instance reproducible (the proof still varies run to run:
    Fcmp.prove draws its blinding factors from secrets.token_bytes, and the pinned
    generator in mic/tests/fcmp/test_units.py closes that off when a test needs it).

    amount / mask build the leaf's amount commitment as mask·G + amount·H instead
    of an opaque random point, needed when the instance has to balance against
    real transaction outputs. r_c pins the commitment re-randomization scalar,
    which the tx balance fixes to Σ k_a − mask. Left None it is random, as it is
    for a standalone proof.
    """
    if seed is not None:
        rng = random.Random(seed)

        def rand():
            return df25519.Scalar(rng.randrange(1, L))

    else:
        rand = df25519.random_scalar

    params = params or _scan.load_params()
    x = rand()
    O = (df25519.G * x).b
    I = carrot.hash_to_point_unbiased(O).b
    if amount is None:
        # The membership proof never opens C, so an opaque point is a valid leaf.
        C = (df25519.G * rand()).b
    else:
        mask = mask if mask is not None else rand()
        C = (df25519.G * mask + df25519.H * df25519.Scalar(amount)).b
    rr = _blinds.Rerandomization(O, I, C, rng=rand, r_c=r_c)

    output = Output(oc_from_bytes(O), oc_from_bytes(I), oc_from_bytes(C))
    tree = build_tree(params, output, layers, rand)

    return Fixture(params, x, O, I, C, rr, tree, amount=amount, mask=mask, rand=rand)


def _batch_rng():
    """Deterministic batch-verifier weights (the shape scan.verify_membership_proof uses)."""
    ctr = [0]

    def rng_fn():
        ctr[0] += 1
        return SeleneField(ctr[0])

    return rng_fn


def wrong_root(root_bytes: bytes) -> bytes:
    """A different tree root that is still a well-formed one.

    point_to_bytes keeps the sign of y in bit 7 of the last byte, so flipping
    that bit and nothing else names the negation of the root: same x, other y,
    still a point on the same curve. Flipping any other bit would usually name an
    x that no point has, and a verifier is then rejecting a malformed root rather
    than the wrong one, which is a weaker thing to have tested and which
    scan.check_membership reports as a checker error rather than a failure.
    """
    return root_bytes[:31] + bytes([root_bytes[31] ^ 0x80])


def verify_membership(proof, root_blind_pok, params, is_c1, root_bytes, layers, inputs):
    """Fcmp.verify + both batch finalizations. Returns (ok, detail).

    The fixture-side counterpart of scan.verify_membership_proof, which starts
    from a parsed transaction instead. Queueing a proof into a batch verifier
    decides nothing until the batch is checked, so both generator sets have to be
    settled before this can say ok.
    """
    v1 = Generators.new_batch_verifier(HeliosField)
    v2 = Generators.new_batch_verifier(SeleneField)
    try:
        Fcmp.verify(
            proof=proof,
            root_blind_pok=root_blind_pok,
            params=params,
            is_c1=is_c1,
            tree_root_bytes=root_bytes,
            layers=layers,
            inputs=inputs,
            verifier_1=v1,
            verifier_2=v2,
            rng_fn=_batch_rng(),
        )
        ok1 = params.curve_1_generators.verify(v1)
        ok2 = params.curve_2_generators.verify(v2)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    if ok1 and ok2:
        return True, "accepted"
    return False, f"batch mismatch C1={ok1} C2={ok2}"


# --------------------------------------------------------------------------- #
#  wrapping the instance in a complete transaction
# --------------------------------------------------------------------------- #
#
# Ordering is the subtle part: the key image comes from the input, the outputs
# need it for their Carrot input context, the outputs then fix the commitment
# re-randomization r_c = Σ k_a − mask, and only with r_c in hand can the fixture
# re-randomize the input. build_tx_fixture does them in that order.


def _kc(b):
    k = keccak.new(digest_bits=256)
    k.update(b)
    return k.digest()


def tx_id(tx) -> bytes:
    """Monero transaction id: keccak(keccak(prefix) ‖ keccak(base) ‖ keccak(prunable))."""
    return _kc(
        _kc(_serialize.serialize_prefix(tx))
        + _kc(_serialize.serialize_rct_base(tx))
        + _kc(_serialize.serialize_rct_prunable(tx))
    )


def _make_output(amount, enote_type, input_context, K_s, K_v):
    """One Carrot v1 sender-side output to a main (legacy) address."""
    anchor = os.urandom(16)
    pid = b"\x00" * 8
    d_e = carrot.enote_ephemeral_privkey(anchor, input_context, K_s, pid)
    D_e = carrot.x25519_base(d_e.b)
    s_sr = carrot.shared_secret_sender(d_e.b, K_v)
    s_ctx = carrot.contextualized_secret(s_sr, D_e, input_context)
    k_a = carrot.amount_blinding_factor(s_ctx, amount, K_s, enote_type)
    C_a = df25519.G * k_a + df25519.H * Scalar(amount)
    kg = carrot.sender_extension_g(s_ctx, C_a.b)
    kt = carrot.sender_extension_t(s_ctx, C_a.b)
    Ko = Point(K_s) + df25519.G * kg + carrot.T * kt
    view_tag = carrot.view_tag(s_sr, input_context, Ko.b)
    m_a = carrot.amount_encryption_mask(s_ctx, Ko.b)
    enc_amount = bytes(p ^ q for p, q in zip(amount.to_bytes(8, "little"), m_a))
    m_anchor = carrot.anchor_encryption_mask(s_ctx, Ko.b)
    enc_anchor = bytes(p ^ q for p, q in zip(anchor, m_anchor))
    return dict(Ko=Ko.b, view_tag=view_tag, enc_anchor=enc_anchor, enc_amount=enc_amount,
                D_e=D_e, C_a=C_a.b, k_a=k_a, amount=amount)


def build_tx_fixture(seed=None, layers: int = 1):
    """Build the fixture and the tx prefix/base, so r_c balances the outputs.

    Returns (fixture, tx_parts, seed), where tx_parts carries the partially built
    Transaction, its outputs, the signable_tx_hash the SAL binds to, and the key
    image.

    A seed is mandatory, so one is drawn when the caller gives none: we derive the
    input's key material here and make_fixture derives it again below, and the two
    only agree if both read the same seeded stream.
    """
    amount_in = PAY + FEE + 1234567890
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "little")

    # Derive the input's key material the same way make_fixture will, so we can
    # compute the key image before the fixture exists.
    rng = random.Random(seed)

    def rand():
        return Scalar(rng.randrange(1, L))

    x = rand()
    O = (df25519.G * x).b
    I = carrot.hash_to_point_unbiased(O).b
    key_image = Point(I) * x  # L = x·Hp(O)
    mask = rand()

    # a synthetic destination address (both outputs go to it)
    k_s, k_v = rand(), rand()
    K_s, K_v = (df25519.G * k_s).b, (df25519.G * k_v).b

    input_context = carrot.input_context_ringct(key_image.b)
    change = amount_in - FEE - PAY
    outs = [
        _make_output(PAY, carrot.ENOTE_TYPE_PAYMENT, input_context, K_s, K_v),
        _make_output(change, carrot.ENOTE_TYPE_CHANGE, input_context, K_s, K_v),
    ]
    # consensus requires outputs sorted by one-time pubkey, strictly ascending
    outs.sort(key=lambda o: o["Ko"])
    r_c = outs[0]["k_a"] + outs[1]["k_a"] - mask

    fx = make_fixture(seed=seed, amount=amount_in, mask=mask, r_c=r_c, layers=layers)
    # make_fixture draws from the same seeded stream in the same order, so it
    # reproduces x/O/I/mask exactly, so check rather than assume.
    if fx.O != O or fx.I != I:
        raise ValueError("fixture key material diverged from the tx setup")

    lhs = Point(fx.rr.C_tilde)
    rhs = Point(outs[0]["C_a"]) + Point(outs[1]["C_a"]) + df25519.H * Scalar(FEE)
    if lhs != rhs:
        raise ValueError("commitment balance failed")

    # prefix + rct base -> signable_tx_hash (the SAL binds to this)
    tx = _serialize.Transaction()
    tx.version = 2
    tx.unlock_time = 0
    tx.vin = [_serialize.TxIn(0, [], key_image.b)]
    tx.vout = [_serialize.CarrotOut(0, o["Ko"], o["view_tag"], o["enc_anchor"]) for o in outs]
    extra = bytearray([0x04, len(outs)])
    for o in outs:
        extra += o["D_e"]
    tx.extra = bytes(extra)
    tx.rct_type = 7
    tx.txnFee = FEE
    tx.ecdhInfo = [o["enc_amount"] for o in outs]
    tx.outPk = [o["C_a"] for o in outs]
    sig_hash = _scan.signable_tx_hash(tx)

    return fx, {"tx": tx, "outs": outs, "sig_hash": sig_hash, "key_image": key_image}, seed


def assemble_tx(tx_parts, fx, mproof, salp) -> bytes:
    """Attach the Bulletproof+ and the prunable part, and serialize. Returns the blob."""
    tx, outs = tx_parts["tx"], tx_parts["outs"]

    bp = check_rangeproofs.prove_bp_plus(
        [Scalar(outs[0]["amount"]), Scalar(outs[1]["amount"])],
        [outs[0]["k_a"], outs[1]["k_a"]],
    )
    tx.bpp = [
        _serialize.BulletproofPlus(
            bp.A.b, bp.A1.b, bp.B.b, bp.r1.b, bp.s1.b, bp.d1.b,
            [p.b for p in bp.L], [p.b for p in bp.R],
        )
    ]

    # There is no chain here, so pick a plausible height and set the tx's
    # reference_block to the lock index that height's block would carry
    # (height + 8), which is what a scan resolves the tree root through.
    # verify-tx ignores it and takes the root explicitly.
    tx.reference_block = DEMO_HEIGHT + _scan.LOCK_OFFSET
    tx.n_tree_layers = fx.layers
    tx.fcmp_pp = (
        fx.rr.O_tilde + fx.rr.I_tilde + fx.rr.R + salp.to_bytes()
        + mproof.proof + mproof.root_blind_pok
    )
    tx.pseudoOuts = [fx.rr.C_tilde]

    blob = _serialize.serialize_tx(tx)
    if _serialize.serialize_tx(_serialize.parse_tx(blob)) != blob:
        raise ValueError("tx round-trip failed: the serializer and parser disagree")
    return blob


def build_sample_tx(seed=None, layers: int = 1) -> dict:
    """Prove, assemble and serialize a complete synthetic FCMP++ transaction.

    Deterministic. The depth picks the seed, PinnedRandomness holds every
    OS-randomness source in the build to it, and the whole build runs inside the
    pin, so the same depth returns the same transaction byte for byte on every
    run and every machine. Passing seed overrides the derived one, for a caller
    that wants a different instance at the same depth.

    Returns everything the tests and the benchmarks need, in memory:
    the fixture, the membership proof, the tree root, the tx object, its blob
    and its id.
    """
    if seed is None:
        seed = seed_for(layers)

    with PinnedRandomness(seed):
        fx, tx_parts, seed = build_tx_fixture(seed, layers)

        bwb = fx.branches()
        root_bytes = fx.root_bytes(bwb)
        mproof = Fcmp.prove(rng_seed=seed, params=fx.params, branches=bwb)

        x, y, r_i, r_r_i = fx.sal_secrets()
        _L, salp = _sal.prove(tx_parts["sig_hash"], fx.rr.O_tilde, fx.rr.I_tilde,
                              fx.rr.R, fx.rr.C_tilde, x, y, r_i, r_r_i)

        blob = assemble_tx(tx_parts, fx, mproof, salp)

    return {
        "fixture": fx,
        "mproof": mproof,
        "sal": salp,
        "root_bytes": root_bytes,
        "tx": tx_parts["tx"],
        "blob": blob,
        "txid": tx_id(tx_parts["tx"]).hex(),
        "layers": layers,
        "seed": seed,
    }


def make_scan_dump(built: dict, height: int = DEMO_HEIGHT) -> dict:
    """A one-block replay dump, in the exact shape scan.RecordingRPC captures.

    Replaying it drives the real scan code path (block fetch, tree-root caching
    by lock index, transaction verification, statistics) with no node.
    """
    txid = built["txid"]
    return {
        "node": "synthetic://sample_tx",
        "calls": {
            "get_block_count": height + 1,
            f"get_block:{height}": {
                "json": json.dumps({"fcmp_pp_tree_root": built["root_bytes"].hex()}),
                "tx_hashes": [txid],
            },
            f"get_transactions:{txid}": {
                "status": "OK",
                "txs": [
                    {
                        "tx_hash": txid,
                        "as_hex": built["blob"].hex(),
                        "as_json": json.dumps(_scan.tx_json_from_blob(built["blob"])),
                    }
                ],
            },
        },
    }


# --------------------------------------------------------------------------- #
#  the finished proof, written out as a block would carry it
# --------------------------------------------------------------------------- #


def proof_record(built_tx: dict) -> dict:
    """The finished proof, in the shape a daemon hands a transaction out in.

    tx is exactly what get_transactions returns decoded, which
    scan.tx_json_from_blob rebuilds from the blob, so the membership proof sits
    where a verifier looks for it, at tx.rctsig_prunable.fcmp_pp, alongside the
    SAL proof and the blinded input tuple that share those bytes.

    tree_root rides along because it is the one thing the proof is meaningless
    without and the one thing the transaction does not carry: on a real chain it
    comes from the block the tx references, and here there is no chain to ask.
    """
    return {
        "layers": built_tx["layers"],
        "seed": built_tx["seed"],
        "block_height": DEMO_HEIGHT,
        "tree_root": built_tx["root_bytes"].hex(),
        "txid": built_tx["txid"],
        "tx_blob": built_tx["blob"].hex(),
        "tx": _scan.tx_json_from_blob(built_tx["blob"]),
    }


def proof_json(built_tx: dict) -> str:
    """proof_record as the text that goes in the file.

    Fixed key order and fixed indentation, so two runs at the same depth are
    identical files and a plain diff is enough to see that they are.
    """
    return json.dumps(proof_record(built_tx), indent=2, sort_keys=True) + "\n"


def proof_path(layers: int, directory: str = None) -> str:
    return os.path.join(directory or PROOF_DIR, f"fcmp_proof_{layers}layers.json")


def write_proof_json(layers: int, directory: str = None) -> str:
    """Write that depth's proof file, creating the directory. Returns the path."""
    path = proof_path(layers, directory)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(proof_json(built(layers)))
    return path


# --------------------------------------------------------------------------- #
#  one build per depth, shared by every test below (and by test_units.py)
# --------------------------------------------------------------------------- #

def expected_proof_bytes(layers: int) -> int:
    """One input's membership proof size at that depth.

    3072 B for the leaf layer alone, then every layer added costs 640 B or 384 B
    depending on which curve it lands on, alternating from 640 upward. That gives
    3072, 4096, 5760 and 6784 B at 1, 3, 6 and 8 layers. The reference
    implementation reports proof_size(1, 8) = 6848 B, which is the 6784 here plus
    the 64-byte root-blind PoK it counts together with the proof.
    """
    added = layers - 1
    return 3072 + 640 * ((added + 1) // 2) + 384 * (added // 2)


_BUILT = {}


def built(layers: int = None) -> dict:
    """build_sample_tx at one depth, memoized: proving is the expensive part.

    No argument means the primary depth, the first one this run was asked for,
    which is what the depth-independent tests use.
    """
    if layers is None:
        layers = primary()
    if layers not in _BUILT:
        _BUILT[layers] = build_sample_tx(layers=layers)
    return _BUILT[layers]


def _statuses(result):
    return {k: v["status"] for k, v in result["checks"].items()}


# --------------------------------------------------------------------------- #
#  the pipeline, at every depth
# --------------------------------------------------------------------------- #


class TestProofPipeline(unittest.TestCase):
    """Prove and verify a real spend at every depth this run was asked for.

    Depth is the only thing that reaches additional_layer and the cross-curve C2
    circuit. A 1-layer instance, where the leaf layer is the root, never does.
    """

    @classmethod
    def setUpClass(cls):
        cls.params = _scan.load_params()
        for n in LAYERS:
            built(n)

    def test_membership_proof_is_accepted(self):
        for n in LAYERS:
            with self.subTest(layers=n):
                b = built(n)
                fx = b["fixture"]
                ok, detail = verify_membership(
                    b["mproof"].proof, b["mproof"].root_blind_pok, fx.params,
                    fx.is_c1, b["root_bytes"], fx.layers, fx.verify_inputs(),
                )
                self.assertTrue(ok, detail)

    def test_membership_proof_size_matches_the_reference(self):
        for n in LAYERS:
            with self.subTest(layers=n):
                self.assertEqual(len(built(n)["mproof"].proof), expected_proof_bytes(n))

    def test_eight_layers_matches_reference_proof_size(self):
        """proof_size(1, 8) = 6848 B in the reference: our 6784 plus the 64-byte PoK.

        Skipped rather than built when this run was not asked for 8 layers, since
        the point of --layers is not to pay for depths nobody asked for.
        """
        if 8 not in LAYERS:
            self.skipTest("8 layers is not among the depths being built")
        self.assertEqual(len(built(8)["mproof"].proof) + 64, 6848)

    def test_tampered_membership_proof_is_rejected(self):
        """A verifier that accepted everything would pass the happy path above."""
        for n in LAYERS:
            with self.subTest(layers=n):
                b = built(n)
                fx = b["fixture"]
                bad = bytearray(b["mproof"].proof)
                bad[len(bad) // 2] ^= 0x01
                ok, _ = verify_membership(
                    bytes(bad), b["mproof"].root_blind_pok, fx.params,
                    fx.is_c1, b["root_bytes"], fx.layers, fx.verify_inputs(),
                )
                self.assertFalse(ok)

    def test_wrong_tree_root_is_rejected(self):
        """A proof only verifies against the root its reference block commits to."""
        for n in LAYERS:
            with self.subTest(layers=n):
                b = built(n)
                fx = b["fixture"]
                ok, _ = verify_membership(
                    b["mproof"].proof, b["mproof"].root_blind_pok, fx.params,
                    fx.is_c1, wrong_root(b["root_bytes"]), fx.layers, fx.verify_inputs(),
                )
                self.assertFalse(ok)

    def test_root_curve_alternates_with_depth(self):
        """Odd depths root on C1/Selene, even depths on C2/Helios."""
        for n in LAYERS:
            with self.subTest(layers=n):
                self.assertEqual(built(n)["fixture"].is_c1, n % 2 == 1)

    def test_computed_root_agrees_with_the_built_tree(self):
        """Fcmp._compute_tree_root derives the root from the root branch alone.

        Agreement confirms the whole layer assignment: which field each level
        lives in, its width, and which curve's generators commit it. root_bytes
        raises on mismatch, so reaching the end is the assertion.
        """
        for n in LAYERS:
            with self.subTest(layers=n):
                fx = built(n)["fixture"]
                fx.root_bytes(fx.branches())

    def test_key_image_matches_the_spend_key(self):
        """The key image in vin[0] must equal x·Hp(O), recomputed independently."""
        for n in LAYERS:
            with self.subTest(layers=n):
                b = built(n)
                fx = b["fixture"]
                self.assertEqual(b["tx"].vin[0].k_image, (Point(fx.I) * fx.x).b)

    def test_sal_proof_size(self):
        for n in LAYERS:
            with self.subTest(layers=n):
                self.assertEqual(len(built(n)["sal"].to_bytes()), 384)


class TestBlockchainProofJson(unittest.TestCase):
    """The proof written out as a block would carry it, and identical every run.

    A proof that came out different on every run would still be a valid proof,
    but nothing downstream could pin it: no golden file, no diff between two
    versions of the prover, no handing someone a transaction and having them
    rebuild the same bytes. So determinism is not assumed here, it is tested, by
    building a second independent transaction at the same depth and demanding
    the two agree exactly.
    """

    @classmethod
    def setUpClass(cls):
        cls.paths = {n: write_proof_json(n) for n in LAYERS}

    def _record(self, layers):
        with open(self.paths[layers]) as f:
            return json.load(f)

    def test_a_file_is_written_for_every_depth(self):
        for n in LAYERS:
            with self.subTest(layers=n):
                self.assertTrue(os.path.exists(self.paths[n]), self.paths[n])

    def test_the_file_carries_the_proof_in_the_daemon_shape(self):
        """The membership proof has to land where a verifier reads it from."""
        for n in LAYERS:
            with self.subTest(layers=n):
                rec, b = self._record(n), built(n)
                self.assertEqual(rec["layers"], n)
                self.assertEqual(rec["seed"], seed_for(n))
                self.assertEqual(rec["tree_root"], b["root_bytes"].hex())
                self.assertEqual(rec["txid"], b["txid"])
                self.assertEqual(rec["tx_blob"], b["blob"].hex())
                prunable = rec["tx"]["rctsig_prunable"]
                self.assertEqual(prunable["n_tree_layers"], n)
                # fcmp_pp is O~(32) I~(32) R(32) SAL(384) membership PoK(64)
                self.assertEqual(
                    len(bytes.fromhex(prunable["fcmp_pp"])),
                    96 + 384 + expected_proof_bytes(n) + 64,
                )

    def test_the_written_file_verifies_on_its_own(self):
        """Read back from disk and run the node's four checks on it, with nothing
        from this process in the loop but the consensus parameters.

        This is what makes the file a proof rather than a dump of one: everything
        needed to reject it if it were wrong is in there.
        """
        params = _scan.load_params()
        for n in LAYERS:
            with self.subTest(layers=n):
                rec = self._record(n)
                r = _scan.verify_tx(
                    rec["tx"], rec["tx_blob"], bytes.fromhex(rec["tree_root"]), params,
                )
                self.assertEqual(
                    _statuses(r),
                    {"membership": "ok", "sal": "ok", "bp": "ok", "balance": "ok"},
                    r["checks"],
                )
                self.assertTrue(r["ok"])

    def test_rebuilding_a_depth_reproduces_the_proof_exactly(self):
        """The whole build again from scratch, and every byte of it must match.

        Not just the membership proof: the tree, the tx, the SAL proof and the
        Bulletproof+ all draw randomness of their own, and any of them left
        unpinned would show up here as a different blob.
        """
        for n in LAYERS:
            with self.subTest(layers=n):
                again, before = build_sample_tx(layers=n), built(n)
                self.assertEqual(again["root_bytes"], before["root_bytes"])
                self.assertEqual(again["mproof"].proof, before["mproof"].proof)
                self.assertEqual(again["mproof"].root_blind_pok,
                                 before["mproof"].root_blind_pok)
                self.assertEqual(again["sal"].to_bytes(), before["sal"].to_bytes())
                self.assertEqual(again["blob"], before["blob"])
                self.assertEqual(again["txid"], before["txid"])
                self.assertEqual(proof_json(again), proof_json(before))

    def test_the_proof_is_a_function_of_the_depth_alone(self):
        """Different depths must still give different proofs, or the reproducibility
        above would hold for the uninteresting reason."""
        blobs = {n: built(n)["blob"] for n in LAYERS}
        self.assertEqual(len(set(blobs.values())), len(LAYERS))


class TestTransactionChecks(unittest.TestCase):
    """The four per-transaction checks, on a complete assembled transaction."""

    def _verify(self, blob, root=None, layers=None, blob_hex=True):
        b = built(layers)
        tx_json = _scan.tx_json_from_blob(blob)
        return _scan.verify_tx(
            tx_json, blob.hex() if blob_hex else None,
            root if root is not None else b["root_bytes"], b["fixture"].params,
        )

    def test_serializer_round_trips(self):
        """parse -> serialize must return the identical bytes.

        A serializer that dropped or reordered a field would still produce a blob
        the checks below accept, because they re-serialize it themselves.
        """
        for n in LAYERS:
            with self.subTest(layers=n):
                blob = built(n)["blob"]
                self.assertEqual(_serialize.serialize_tx(_serialize.parse_tx(blob)), blob)

    def test_all_four_checks_pass_at_every_depth(self):
        for n in LAYERS:
            with self.subTest(layers=n):
                r = self._verify(built(n)["blob"], layers=n)
                self.assertEqual(
                    _statuses(r),
                    {"membership": "ok", "sal": "ok", "bp": "ok", "balance": "ok"},
                    r["checks"],
                )
                self.assertTrue(r["ok"])
                self.assertEqual(r["n_inputs"], 1)
                self.assertEqual(r["n_tree_layers"], n)

    # -- each check is load-bearing, depth-independent, run at the primary depth --

    def _corrupt_fcmp_pp(self, offset):
        """Flip a byte inside the tx's fcmp_pp blob, returning the new tx blob."""
        tx = _serialize.parse_tx(built()["blob"])
        pp = bytearray(tx.fcmp_pp)
        pp[offset] ^= 0x01
        tx.fcmp_pp = bytes(pp)
        return _serialize.serialize_tx(tx)

    def test_corrupt_membership_proof_fails_membership_only(self):
        # layout: O~(32) I~(32) R(32) SAL(384) | membership body | PoK(64)
        st = _statuses(self._verify(self._corrupt_fcmp_pp(480 + 512)))
        self.assertEqual(st["membership"], "fail")
        self.assertEqual(st["sal"], "ok")
        self.assertEqual(st["bp"], "ok")
        self.assertEqual(st["balance"], "ok")

    def test_corrupt_sal_proof_fails_sal_only(self):
        st = _statuses(self._verify(self._corrupt_fcmp_pp(96 + 200)))  # inside the 384-byte SAL
        self.assertEqual(st["sal"], "fail")
        self.assertEqual(st["membership"], "ok")
        self.assertEqual(st["bp"], "ok")
        self.assertEqual(st["balance"], "ok")

    def test_corrupt_range_proof_fails_bp_only(self):
        tx = _serialize.parse_tx(built()["blob"])
        bad = bytearray(tx.bpp[0].r1)
        bad[0] ^= 0x01
        tx.bpp[0].r1 = bytes(bad)
        st = _statuses(self._verify(_serialize.serialize_tx(tx)))
        self.assertEqual(st["bp"], "fail")
        self.assertEqual(st["membership"], "ok")
        self.assertEqual(st["balance"], "ok")

    def test_inflated_fee_breaks_balance(self):
        """The inflation attempt the checker exists to catch.

        The amounts are hidden, so the only thing pinning them is
        Σ pseudoOuts = Σ outPk + fee·H.
        """
        tx = _serialize.parse_tx(built()["blob"])
        tx.txnFee += 1
        st = _statuses(self._verify(_serialize.serialize_tx(tx)))
        self.assertEqual(st["balance"], "fail")
        # The fee is part of the rct base, so the signable hash moves and the SAL
        # no longer matches either: a second, independent line of defence.
        self.assertEqual(st["sal"], "fail")

    def test_wrong_tree_root_fails_membership(self):
        """fail, not error: a real root that the proof does not open is an invalid
        transaction, not a checker that could not make up its mind."""
        r = self._verify(built()["blob"], root=wrong_root(built()["root_bytes"]))
        self.assertEqual(r["checks"]["membership"]["status"], "fail")

    def test_sal_is_skipped_without_the_blob(self):
        """Without the raw blob the SAL check reports skip, not a false pass."""
        r = self._verify(built()["blob"], blob_hex=False)
        self.assertEqual(r["checks"]["sal"]["status"], "skip")
        self.assertFalse(r["ok"])
        self.assertEqual(r["skipped"], ["sal"])


# --------------------------------------------------------------------------- #
#  the block loop, driven offline through a replay dump
# --------------------------------------------------------------------------- #


class _Args:
    """Stand-in for the parsed CLI namespace scan.run consumes."""

    def __init__(self, **kw):
        self.node = _scan.DEFAULT_NODE
        self.start_height = DEMO_HEIGHT
        self.end_height = None
        self.checks = ",".join(_scan.ALL_CHECKS)
        self.params = None
        self.record = None
        self.replay = None
        self.poll_interval = 0.1
        self.once = True
        self.max_retries = 1
        self.timeout = 5.0
        self.quiet = True
        self.__dict__.update(kw)


class TestScanReplay(unittest.TestCase):
    """The real scan path (block fetch, tree-root caching by lock index,
    per-transaction verification, statistics) with no node in the loop."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="fcmp_scan_")
        cls.b = built()
        cls.dump_json = make_scan_dump(cls.b)
        cls.dump = os.path.join(cls.tmp, "sample_scan_dump.json")
        with open(cls.dump, "w") as f:
            json.dump(cls.dump_json, f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_dump_has_the_recorded_shape(self):
        self.assertIn(f"get_block:{DEMO_HEIGHT}", self.dump_json["calls"])
        self.assertIn(f"get_transactions:{self.b['txid']}", self.dump_json["calls"])

    def test_replay_rpc_serves_the_block(self):
        rpc = _scan.ReplayRPC(self.dump)
        block = rpc.get_block(DEMO_HEIGHT)
        self.assertEqual(len(block["tx_hashes"]), 1)
        root = json.loads(block["json"])["fcmp_pp_tree_root"]
        self.assertEqual(root, self.b["root_bytes"].hex())

    def test_tree_root_resolved_through_the_lock_index(self):
        """A tx's reference_block is a lock index: the root lives in block K − 8."""
        rpc = _scan.ReplayRPC(self.dump)
        root = _scan.tree_root_for(rpc, DEMO_HEIGHT + _scan.LOCK_OFFSET, {})
        self.assertEqual(root, self.b["root_bytes"])

    def test_scan_verifies_the_block(self):
        """Every check passes, and the run reports no failures."""
        self.assertEqual(_scan.run(_Args(replay=self.dump)), 0)

    def test_inflating_a_tx_in_the_dump_makes_the_scan_exit_non_zero(self):
        """An inflated fee in a replayed block must make the whole run exit 1.

        This is the end of the chain the tool exists for: a transaction claiming
        more than its commitments allow has to survive no check, be counted as a
        failure rather than a checker error, and change the process exit code.
        """
        tx = _serialize.parse_tx(self.b["blob"])
        tx.txnFee += 1
        bad_blob = _serialize.serialize_tx(tx)

        d = json.loads(json.dumps(self.dump_json))
        entry = d["calls"][f"get_transactions:{self.b['txid']}"]["txs"][0]
        entry["as_hex"] = bad_blob.hex()
        entry["as_json"] = json.dumps(_scan.tx_json_from_blob(bad_blob))

        bad_path = os.path.join(self.tmp, "bad_dump.json")
        with open(bad_path, "w") as f:
            json.dump(d, f)

        self.assertEqual(_scan.run(_Args(replay=bad_path)), 1)


# --------------------------------------------------------------------------- #
#  the command line
# --------------------------------------------------------------------------- #


def _build_arg_parser():
    p = argparse.ArgumentParser(
        prog="python -m mic.tests.fcmp.test_end_to_end",
        description=(
            "Build a complete FCMP++ spend at the given tree depths, verify it every "
            "way a node would, and write each one out as a blockchain-shaped JSON "
            "proof. The build is deterministic: a depth always yields the same "
            "transaction. Any further arguments go to unittest."
        ),
    )
    default = ",".join(str(n) for n in DEFAULT_LAYERS)
    p.add_argument("--layers", default=None, metavar="N[,N...]",
                   help=f"tree depths to build, deeper is slower (default {default})")
    p.add_argument("--proof-dir", default=None, metavar="DIR",
                   help=f"where to write fcmp_proof_<n>layers.json (default {PROOF_DIR})")
    return p


def _main(argv=None):
    """Pick the depths off the command line, then hand the rest to unittest."""
    global LAYERS, PROOF_DIR
    parser = _build_arg_parser()
    args, rest = parser.parse_known_args(argv)
    if args.layers:
        try:
            LAYERS = _parse_layers(args.layers)
        except ValueError as e:
            parser.error(f"--layers: {e}")
    if args.proof_dir:
        PROOF_DIR = os.path.abspath(args.proof_dir)

    print(f"tree depths : {', '.join(str(n) for n in LAYERS)}")
    print(f"proof files : {PROOF_DIR}")
    print()

    run = unittest.main(argv=[sys.argv[0]] + rest, exit=False, verbosity=2)

    print()
    for n in LAYERS:
        path = proof_path(n)
        if os.path.exists(path):
            print(f"{n:>2} layers -> {path}")
    return 0 if run.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(_main())
