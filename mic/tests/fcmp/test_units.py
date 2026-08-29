#!/usr/bin/env python3
"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

To run it:

    python -m unittest mic.tests.fcmp.test_units --verbose

Sections:

     1. point decoding and low-order rejection
     2. constant-time scalar multiplication bindings
     3. multiexp
     4. the vector commitment tape
     5. Generalized-Bulletproofs vectors and generators
     6. generator growth and capacity
     7. the Fiat-Shamir transcript
     8. EC divisors
     9. circuit generator tables
    10. gadget constraints
    11. consensus parameter loading
    12. transaction serialization
    13. transaction parsing
    14. check classification
    15. the balance and range-proof checks in isolation
"""

import copy
import inspect
import random
import unittest

from mic.fcmp import PARAMS_FILE
from mic.fcmp import gadgets
from mic.fcmp.bindings import ct
from mic.fcmp.circuit import CurveSpec, GeneratorTable
from mic.fcmp.curve import (
    HELIOS_B, HELIOS_G, HELIOS_GX, HELIOS_GY,
    SELENE, SELENE_B, SELENE_GX, SELENE_GY,
    WEI25519, WPoint, _OC_P, _is_low_order_wei25519, _scalar_mul_jacobian,
    oc_from_bytes,
)
from mic.fcmp.divisors import _compute_line, _decompose
from mic.fcmp.field import HeliosField, SeleneField
from mic.fcmp.gbp import (
    Generators,
    InsufficientGenerators,
    PointVector,
    ProverTranscript,
    ScalarVector,
    VerifierTranscript,
)
from mic.fcmp.multiexp import STRAUS_MAX_TERMS, _multiexp_pure, multiexp
from mic.fcmp.proof import Fcmp
from mic.fcmp.tape import VectorCommitmentTape
from mic.tools import scan as _scan
from mic.txlib import serialize as _serialize

from mic.tests.fcmp.test_end_to_end import PinnedRandomness, built, make_fixture

# The Ed25519 basepoint, compressed.
B_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")


# ---------------------------------------------------------------------------
# 1. Point decoding and low-order rejection
# ---------------------------------------------------------------------------


class TestPointDecoding(unittest.TestCase):

    def test_valid_ed25519_point_accepted(self):
        self.assertIsNotNone(oc_from_bytes(B_COMPRESSED), "the basepoint must be accepted")

    def test_all_zeros_returns_none(self):
        self.assertIsNone(oc_from_bytes(bytes(32)), "identity (all zeros) should return None")

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            oc_from_bytes(bytes(31))

    def test_non_canonical_y_returns_none(self):
        # y >= p is rejected: encode _OC_P (= 2^255 - 19) little-endian.
        self.assertIsNone(oc_from_bytes(_OC_P.to_bytes(32, "little")), "y >= p must be rejected")

    def test_basepoint_is_not_low_order(self):
        self.assertIsNotNone(oc_from_bytes(B_COMPRESSED))

    def test_low_order_helper_rejects_an_off_curve_pair(self):
        self.assertFalse(_is_low_order_wei25519(1, 1))


# ---------------------------------------------------------------------------
# 2. Constant-time scalar multiplication bindings
# ---------------------------------------------------------------------------
#
# Swapping the scalar-multiplication backend is only safe if it computes the same
# group elements, so the Montgomery ladder is checked against this repo's pure
# Python arithmetic, which is the definition of correct here. The constant-time
# property itself is measured in benchmarks/bench_ct.py 

CURVES = (
    ("selene", SeleneField, SELENE_B, SELENE_GX, SELENE_GY),
    ("helios", HeliosField, HELIOS_B, HELIOS_GX, HELIOS_GY),
)


@unittest.skipUnless(ct.HAVE_CT, "helioselene_ct not built (bash mic/fcmp/bindings/build.sh)")
class TestConstantTimeBindings(unittest.TestCase):

    def test_scalar_mul_matches_pure_python(self):
        """k·G through the ladder equals the pure-Python double-and-add."""
        rng = random.Random(7)
        for name, F, B, gx, gy in CURVES:
            G = WPoint(F, B, gx, gy)
            for k in [1, 2, 3, (1 << 251), F.P - 1] + [rng.randrange(1, F.P) for _ in range(3)]:
                with self.subTest(curve=name, k=k):
                    self.assertEqual(G * k, _scalar_mul_jacobian(G, k))

    def test_scalar_mul_is_the_live_path(self):
        """WPoint.__mul__ really routes through the ladder, not the fallback."""
        self.assertIn("constant-time", ct.backend())

    def test_identity_and_zero(self):
        for name, F, B, gx, gy in CURVES:
            with self.subTest(curve=name):
                self.assertTrue((WPoint(F, B, gx, gy) * 0).is_identity())
                self.assertTrue((WPoint.identity(F, B) * 5).is_identity())

    def test_negative_scalar(self):
        for name, F, B, gx, gy in CURVES:
            with self.subTest(curve=name):
                G = WPoint(F, B, gx, gy)
                self.assertEqual(G * -3, -(G * 3))


# ---------------------------------------------------------------------------
# 3. Multiexp
# ---------------------------------------------------------------------------


@unittest.skipUnless(ct.HAVE_CT, "helioselene_ct not built (bash mic/fcmp/bindings/build.sh)")
class TestMultiexp(unittest.TestCase):

    def test_msm_matches_pure_python(self):
        """Both native multiexps equal the term-by-term sum.

        The term counts straddle STRAUS_MAX_TERMS from both sides, so this covers
        the interleaved-wNAF path, the bucket path, and the dispatch boundary
        between them. Extend the list, not the constant, if the boundary moves.
        """
        rng = random.Random(11)
        boundary = (STRAUS_MAX_TERMS - 1, STRAUS_MAX_TERMS, STRAUS_MAX_TERMS + 1)
        for name, F, B, gx, gy in CURVES:
            G = WPoint(F, B, gx, gy)
            for n in (1, 2, 3, 4, 8, 9, 17, 64) + boundary:
                pairs = [(F(rng.randrange(1, F.P)), G * rng.randrange(1, 1 << 64))
                         for _ in range(n)]
                with self.subTest(curve=name, terms=n):
                    ident = WPoint.identity(F, B)
                    self.assertEqual(multiexp(pairs, ident), _multiexp_pure(pairs, ident))

    def test_msm_empty_and_all_zero(self):
        for name, F, B, gx, gy in CURVES:
            with self.subTest(curve=name):
                G, ident = WPoint(F, B, gx, gy), WPoint.identity(F, B)
                self.assertTrue(multiexp([], ident).is_identity())
                self.assertTrue(multiexp([(F(0), G), (F(0), G)], ident).is_identity())

    def test_msm_cancels_to_identity(self):
        """k·G + (−k)·G = identity, exercising the bucket accumulator's edge."""
        for name, F, B, gx, gy in CURVES:
            with self.subTest(curve=name):
                G, ident = WPoint(F, B, gx, gy), WPoint.identity(F, B)
                self.assertTrue(multiexp([(F(5), G), (F(5), -G)], ident).is_identity())

    def test_identity_input_is_skipped(self):
        """An identity term contributes nothing, on both native paths.

        The IPA folds generator vectors through multiexp two terms at a time, so a
        mishandled identity here is a wrong proof rather than a slow one.
        """
        for name, F, B, gx, gy in CURVES:
            with self.subTest(curve=name):
                G, ident = WPoint(F, B, gx, gy), WPoint.identity(F, B)
                self.assertEqual(multiexp([(F(3), G), (F(4), ident)], ident), G * 3)
                self.assertEqual(multiexp([(F(4), ident), (F(3), G)], ident), G * 3)


# ---------------------------------------------------------------------------
# 4. The vector commitment tape
# ---------------------------------------------------------------------------


class TestTape(unittest.TestCase):

    def test_bad_commitment_len(self):
        with self.assertRaises(ValueError):
            VectorCommitmentTape(HeliosField, 127)  # not divisible by 128

    def test_bad_variable_count(self):
        tape = VectorCommitmentTape(HeliosField, 128)
        with self.assertRaises(ValueError):
            tape.append([HeliosField(0)] * 5)  # must be exactly COMMITMENT_WORD_LEN

    def test_append_branch_bad_offset(self):
        # commitment_len 256 leaves the offset mid-chunk after one append. At 128
        # it would wrap straight back to 0 and the guard would not be reached.
        tape = VectorCommitmentTape(HeliosField, 256)
        tape.append()  # offset = 128, not 0 yet
        with self.assertRaises(ValueError):
            tape.append_branch(10)

    def test_append_branch_zero_length(self):
        with self.assertRaises(ValueError):
            VectorCommitmentTape(HeliosField, 128).append_branch(0)

    def test_append_branch_too_long(self):
        with self.assertRaises(ValueError):
            VectorCommitmentTape(HeliosField, 128).append_branch(129)

    def test_dlog_scalar_bits_too_large(self):
        with self.assertRaises(ValueError):
            VectorCommitmentTape(HeliosField, 256).append_dlog(256)

    def test_commit_blinds_mismatch(self):
        tape = VectorCommitmentTape(HeliosField, 128)
        tape.append()
        with self.assertRaises(ValueError):
            tape.commit([HELIOS_G] * 128, HELIOS_G, [])  # no blinds but 1 commitment


# ---------------------------------------------------------------------------
# 5. Generalized-Bulletproofs vectors and generators
# ---------------------------------------------------------------------------


class TestGbpVectors(unittest.TestCase):

    def test_scalar_vector_add_mismatch(self):
        with self.assertRaises(ValueError):
            _ = ScalarVector([HeliosField(1), HeliosField(2)]) + ScalarVector([HeliosField(1)])

    def test_scalar_vector_sub_mismatch(self):
        with self.assertRaises(ValueError):
            _ = ScalarVector([HeliosField(1)]) - ScalarVector([HeliosField(1), HeliosField(2)])

    def test_scalar_vector_mul_mismatch(self):
        with self.assertRaises(ValueError):
            _ = ScalarVector([HeliosField(1), HeliosField(2)]) * ScalarVector([HeliosField(3)])

    def test_point_vector_split_odd(self):
        with self.assertRaises(ValueError):
            PointVector([HELIOS_G, HELIOS_G, HELIOS_G]).split()

    def test_generators_g_bold_h_bold_mismatch(self):
        id_pt = WPoint.identity(HeliosField, HELIOS_B)
        with self.assertRaises(ValueError):
            Generators(HELIOS_G, HELIOS_G, [HELIOS_G] * 4, [HELIOS_G] * 8, id_pt)

    def test_generators_not_power_of_two(self):
        id_pt = WPoint.identity(HeliosField, HELIOS_B)
        with self.assertRaises(ValueError):
            Generators(HELIOS_G, HELIOS_G, [HELIOS_G] * 3, [HELIOS_G] * 3, id_pt)


# ---------------------------------------------------------------------------
# 6. Generator growth and capacity
# ---------------------------------------------------------------------------


class TestGeneratorSizing(unittest.TestCase):
    """A transaction's circuit size grows with its input count.

    Fixing the generator count at load time made every many-input transaction
    crash the verifier: reduce() returned None and the None only surfaced as an
    AttributeError deep inside the circuit, which the scan logged as a check
    'error' with no detail. 63 transactions in one testnet scan died that way.
    """

    @classmethod
    def setUpClass(cls):
        cls.params = _scan.load_params(PARAMS_FILE)

    def test_reduce_grows_past_the_initial_size(self):
        # (inputs, layers) shapes taken from a real FCMP++ testnet scan. Every one
        # of these needs more than the 512/256 generators loaded up front.
        for inputs, layers in ((3, 5), (4, 5), (7, 5)):
            with self.subTest(inputs=inputs, layers=layers):
                c1_rows, c2_rows = Fcmp.ipa_rows(inputs, layers)
                c1 = self.params.curve_1_generators.reduce(c1_rows)
                c2 = self.params.curve_2_generators.reduce(c2_rows)
                self.assertIsNotNone(c1, f"{inputs} inputs/{layers} layers: no C1 generators")
                self.assertIsNotNone(c2, f"{inputs} inputs/{layers} layers: no C2 generators")
                self.assertEqual(c1.len(), c1_rows)
                self.assertEqual(c2.len(), c2_rows)

    def test_capacity_covers_the_widest_observed_transaction(self):
        """An 86-input spend really appears on chain, and it needs 32768 generators."""
        c1_rows, c2_rows = Fcmp.ipa_rows(86, 5)
        self.assertGreaterEqual(self.params.curve_1_generators._capacity, c1_rows)
        self.assertGreaterEqual(self.params.curve_2_generators._capacity, c2_rows)

    def test_reduce_beyond_capacity_raises(self):
        with self.assertRaises(InsufficientGenerators):
            self.params.curve_1_generators.reduce(self.params.curve_1_generators._capacity * 2)

    def test_shortfall_is_a_checker_error_not_a_failed_transaction(self):
        """The exception type decides whether a scan cries inflation.

        scan._classify treats ValueError as 'this transaction is invalid'. Running
        out of generators is a limit of this tool, so it must not classify that
        way: a false inflation alarm is worse than an honest crash.
        """
        status, _ = _scan._classify(InsufficientGenerators("out of generators"))
        self.assertEqual(status, "error")


class TestGeneratorGrowthBookkeeping(unittest.TestCase):
    """Growing a set must leave it identical to one built at that size."""

    @staticmethod
    def _build(initial, capacity):
        id_pt = WPoint.identity(HeliosField, HELIOS_B)
        pts = [HELIOS_G * (i + 1) for i in range(capacity)]

        def extend(start, stop):
            return (pts[start:stop], pts[start:stop])

        g_bold, h_bold = extend(0, initial)
        return Generators(HELIOS_G, HELIOS_G, g_bold, h_bold, id_pt,
                          extend=extend, capacity=capacity), pts, id_pt

    def test_h_sum_after_growth_matches_a_fresh_set(self):
        grown, pts, id_pt = self._build(initial=2, capacity=16)
        grown.reduce(16)
        fresh = Generators(HELIOS_G, HELIOS_G, pts[:16], pts[:16], id_pt)

        self.assertEqual(len(grown._h_sum), len(fresh._h_sum))
        for i, (a, b) in enumerate(zip(grown._h_sum, fresh._h_sum)):
            self.assertTrue(a == b, f"h_sum[{i}] diverged after growth")
        self.assertEqual(grown._g_bold, fresh._g_bold)

    def test_a_set_without_a_loader_cannot_grow(self):
        id_pt = WPoint.identity(HeliosField, HELIOS_B)
        fixed = Generators(HELIOS_G, HELIOS_G, [HELIOS_G] * 4, [HELIOS_G] * 4, id_pt)
        self.assertEqual(fixed.reduce(4).len(), 4)
        with self.assertRaises(InsufficientGenerators):
            fixed.reduce(8)


class TestBatchVerifierNotTruncated(unittest.TestCase):
    """Dropping a claim past the end of a vector would pass it unchecked."""

    def test_verify_rejects_more_claims_than_generators(self):
        id_pt = WPoint.identity(HeliosField, HELIOS_B)
        gens = Generators(HELIOS_G, HELIOS_G, [HELIOS_G] * 4, [HELIOS_G] * 4, id_pt)
        v = Generators.new_batch_verifier(SeleneField)
        v.g_bold = [SeleneField(1)] * 8  # more claims than there are generators
        with self.assertRaises(InsufficientGenerators):
            gens.verify(v)


# ---------------------------------------------------------------------------
# 7. The Fiat-Shamir transcript
# ---------------------------------------------------------------------------


class TestTranscript(unittest.TestCase):

    def test_prover_bad_context(self):
        with self.assertRaises(ValueError):
            ProverTranscript(bytes(31))

    def test_verifier_bad_context(self):
        with self.assertRaises(ValueError):
            VerifierTranscript(bytes(31), b"")

    def test_verifier_is_exhausted(self):
        self.assertTrue(VerifierTranscript(bytes(32), b"").is_exhausted())

    def test_verifier_not_exhausted(self):
        self.assertFalse(VerifierTranscript(bytes(32), b"\x00" * 10).is_exhausted())


# ---------------------------------------------------------------------------
# 8. EC divisors
# ---------------------------------------------------------------------------


class TestScalarDecomposition(unittest.TestCase):

    def test_decompose_sum_invariant(self):
        # scalar=0 is rejected by ScalarDecomposition before _decompose is called,
        # so exercise _decompose directly with valid scalars.
        p = SeleneField.P
        for s in [1, 2, 7, 100, p - 1]:
            with self.subTest(scalar=s):
                self.assertEqual(sum(_decompose(s, 253, p)), 253)

    def test_decompose_reconstructs_scalar(self):
        p = SeleneField.P
        s = 12345
        d = _decompose(s, 253, p)
        # The decomposition may add the modulus to force sum == num_bits, so the
        # reconstruction agrees mod p.
        self.assertEqual(sum(d[i] * (1 << i) for i in range(253)) % p, s % p)


class TestComputeLineGuards(unittest.TestCase):
    """A tangent at a 2-torsion point (y = 0) has a zero denominator."""

    def test_tangent_at_2torsion_raises_on_wei25519(self):
        with self.assertRaises(ValueError):
            _compute_line(1, 0, False, 1, 0, False, WEI25519)

    def test_tangent_at_2torsion_raises_on_selene(self):
        # The same guard, with the curve parameter carrying a different base field.
        with self.assertRaises(ValueError):
            _compute_line(1, 0, False, 1, 0, False, SELENE)


# ---------------------------------------------------------------------------
# 9. Circuit generator tables
# ---------------------------------------------------------------------------


class TestGeneratorTableOnCurve(unittest.TestCase):

    def test_valid_base_point_accepted(self):
        spec = CurveSpec(SeleneField(SeleneField.P - 3), SELENE_B)
        self.assertIsNotNone(GeneratorTable(spec, SELENE_GX, SELENE_GY, 4))

    def test_off_curve_base_point_rejected(self):
        spec = CurveSpec(HeliosField(HeliosField.P - 3), HELIOS_B)
        bad_x = HeliosField(HELIOS_GX.v + 1)  # +1 puts it off the curve
        with self.assertRaises(ValueError):
            GeneratorTable(spec, bad_x, HELIOS_GY, 4)


# ---------------------------------------------------------------------------
# 10. Gadget constraints
# ---------------------------------------------------------------------------

TOKEN_SEED = 4242


def prove_pinned(fixture, token_seed: int = TOKEN_SEED, rng_seed: int = 1) -> tuple:
    """Prove fixture's statement with all randomness pinned. Returns (mproof, root_bytes).

    The pin is test_end_to_end.PinnedRandomness, the same one that makes the
    sample transactions there reproducible, so there is one answer in the suite
    to what counts as an OS-randomness source.
    """
    with PinnedRandomness(token_seed):
        # Inside the pin: the branch blinds are drawn here, not in prove().
        branches = fixture.branches()
        root_bytes = fixture.root_bytes(branches)
        mproof = Fcmp.prove(rng_seed=rng_seed, params=fixture.params, branches=branches)
    return mproof, root_bytes


class TestDlogAliasingEnforced(unittest.TestCase):
    """first_layer must reject a witness whose U and V dlog wires are distinct.

    The aliasing is the reason i_blind cannot open to a different scalar on each
    generator. It used to be an assert, which python -O strips, taking the whole
    constraint with it and leaving nothing to notice. This test de-aliases the
    wires on purpose and expects a raise.
    """

    def test_dealiased_dlog_is_rejected(self):
        real = gadgets.first_layer
        sig = inspect.signature(real)

        def probe(*a, **k):
            b = sig.bind(*a, **k)
            b.apply_defaults()
            v = copy.copy(b.arguments["i_blind_v"])
            v.dlog = list(b.arguments["i_blind_u"].dlog)  # equal, not identical
            b.arguments["i_blind_v"] = v
            return real(*b.args, **b.kwargs)

        gadgets.first_layer = probe
        try:
            fx = make_fixture(seed=5, layers=1)
            with self.assertRaises(ValueError):
                prove_pinned(fx)
        finally:
            gadgets.first_layer = real


class TestPinnedProvingIsReproducible(unittest.TestCase):
    """Same fixture seed + same token seed => the same proof bytes.

    Without this the section above proves nothing: a test that pins the
    randomness and still gets a different witness each run cannot demand an exact
    failure from the prover.
    """

    def test_two_pinned_proves_agree(self):
        a, root_a = prove_pinned(make_fixture(seed=17, layers=1))
        b, root_b = prove_pinned(make_fixture(seed=17, layers=1))
        self.assertEqual(root_a, root_b)
        self.assertEqual(a.proof, b.proof)
        self.assertEqual(a.root_blind_pok, b.root_blind_pok)


# ---------------------------------------------------------------------------
# 11. Consensus parameter loading
# ---------------------------------------------------------------------------


class TestLoadParams(unittest.TestCase):
    """input_params.txt carries the generators consensus fixes, and decoding
    them wrong is silent. Every proof simply stops verifying."""

    @classmethod
    def setUpClass(cls):
        cls.params = _scan.load_params(PARAMS_FILE)

    def test_default_path_is_the_shipped_file(self):
        """load_params() with no argument must find the packaged params."""
        self.assertIsNotNone(_scan.load_params().G_table)

    def test_generator_sets_load_at_their_initial_size(self):
        self.assertEqual(len(self.params.curve_1_generators.g_bold_slice()), 512)
        self.assertEqual(len(self.params.curve_2_generators.g_bold_slice()), 256)

    def test_hash_inits_live_on_the_right_curves(self):
        """C1 nodes are Selene points, C2 nodes are Helios points, and swapping them
        would make every tree root come out on the wrong curve."""
        self.assertIs(self.params.curve_1_hash_init.field_cls, SeleneField)
        self.assertIs(self.params.curve_2_hash_init.field_cls, HeliosField)

    def test_all_six_generator_tables_are_present(self):
        for name in ("G_table", "T_table", "U_table", "V_table", "H_1_table", "H_2_table"):
            with self.subTest(table=name):
                self.assertIsInstance(getattr(self.params, name), GeneratorTable)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            _scan.load_params("/nonexistent/input_params.txt")

    def test_collect_stops_at_the_first_gap(self):
        """_collect indexes prefix[0], prefix[1], … and must not skip a hole:
        a silently short generator vector is a verifier that fails at depth."""
        kv = {"g[0]": "a", "g[1]": "b", "g[3]": "d"}
        self.assertEqual(_scan._collect(kv, "g"), ["a", "b"])


# ---------------------------------------------------------------------------
# 12. Transaction serialization
# ---------------------------------------------------------------------------


class TestSerialization(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.blob = built(1)["blob"]
        cls.tx = _serialize.parse_tx(cls.blob)

    def test_round_trip_is_byte_identical(self):
        self.assertEqual(_serialize.serialize_tx(_serialize.parse_tx(self.blob)), self.blob)

    def test_blob_too_short_to_hold_a_transaction_raises_eof(self):
        """Running off the end of the buffer must raise, not return a half tx."""
        with self.assertRaises(EOFError):
            _serialize.parse_tx(self.blob[:64])

    def test_fcmp_pp_takes_the_rest_of_the_buffer(self):
        """fcmp_pp is not length-prefixed: it is whatever follows the fixed fields.

        So the serializer layer cannot notice a blob cut inside it. A truncated
        blob parses, and re-serializes to exactly the truncated bytes. The length
        of the proof is checked one layer up, by parse_fcmp_tx against the input
        count (§13). 
        """
        cut = self.blob[:-100]
        tx = _serialize.parse_tx(cut)
        self.assertEqual(len(tx.fcmp_pp), len(self.tx.fcmp_pp) - 100)
        self.assertEqual(_serialize.serialize_tx(tx), cut)

    def test_tx_json_mirrors_the_daemon_shape(self):
        j = _scan.tx_json_from_blob(self.blob)
        self.assertEqual(j["rct_signatures"]["type"], _scan.RCT_TYPE_FCMP)
        self.assertEqual(j["rct_signatures"]["txnFee"], self.tx.txnFee)
        self.assertEqual(len(j["rct_signatures"]["outPk"]), 2)
        self.assertEqual(len(j["vin"]), 1)
        self.assertEqual(j["vin"][0]["key"]["k_image"], self.tx.vin[0].k_image.hex())
        self.assertEqual(j["rctsig_prunable"]["n_tree_layers"], 1)
        self.assertEqual(j["rctsig_prunable"]["fcmp_pp"], self.tx.fcmp_pp.hex())
        self.assertEqual(j["rctsig_prunable"]["pseudoOuts"],
                         [p.hex() for p in self.tx.pseudoOuts])

    def test_signable_hash_covers_the_fee(self):
        """The SAL binds to keccak(prefix)‖keccak(rct base), and the fee is in the
        base, so touching the fee has to move the hash."""
        before = _scan.signable_tx_hash(self.tx)
        tx = _serialize.parse_tx(self.blob)
        tx.txnFee += 1
        self.assertNotEqual(_scan.signable_tx_hash(tx), before)


# ---------------------------------------------------------------------------
# 13. Transaction parsing
# ---------------------------------------------------------------------------


class TestParseFcmpTx(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tx_json = _scan.tx_json_from_blob(built(1)["blob"])

    def test_non_fcmp_transaction_returns_none(self):
        j = copy.deepcopy(self.tx_json)
        j["rct_signatures"]["type"] = 6  # RCTTypeBulletproofPlus
        self.assertIsNone(_scan.parse_fcmp_tx(j))

    def test_layout_is_sliced_correctly(self):
        p = _scan.parse_fcmp_tx(self.tx_json)
        blob_len = len(bytes.fromhex(self.tx_json["rctsig_prunable"]["fcmp_pp"]))
        self.assertEqual(p["n_inputs"], 1)
        self.assertEqual(p["n_tree_layers"], 1)
        self.assertEqual(len(p["root_blind_pok"]), 64)
        # per input: O~|I~|R|SAL = 480 bytes, then the body, then the 64-byte PoK
        self.assertEqual(len(p["proof_bytes"]), blob_len - 480 - 64)
        self.assertEqual(set(p["inputs"][0]), {"O_tilde", "I_tilde", "R", "C_tilde"})

    def test_no_vin_raises(self):
        j = copy.deepcopy(self.tx_json)
        j["vin"] = []
        with self.assertRaises(ValueError):
            _scan.parse_fcmp_tx(j)

    def test_truncated_fcmp_pp_raises(self):
        j = copy.deepcopy(self.tx_json)
        j["rctsig_prunable"]["fcmp_pp"] = j["rctsig_prunable"]["fcmp_pp"][:200]
        with self.assertRaises(ValueError):
            _scan.parse_fcmp_tx(j)

    def test_undecodable_input_point_raises(self):
        """A point that is not on the curve is bad data, not a broken checker."""
        j = copy.deepcopy(self.tx_json)
        j["rctsig_prunable"]["pseudoOuts"] = ["00" * 32]
        with self.assertRaises(ValueError):
            _scan.parse_fcmp_tx(j)


# ---------------------------------------------------------------------------
# 14. Check classification
# ---------------------------------------------------------------------------


class TestCheckerErrorsAreNotProofFailures(unittest.TestCase):
    """A bug in this tool must report as 'error', never as a failed proof.
    """

    def test_classifier_splits_by_exception_type(self):
        for exc in (ValueError("bad point"), EOFError("truncated"), KeyError("outPk"),
                    IndexError("short")):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(_scan._classify(exc)[0], "fail")
        for exc in (TypeError("our bug"), AttributeError("our bug"), ZeroDivisionError()):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(_scan._classify(exc)[0], "error")

    def test_error_detail_carries_the_traceback(self):
        """'error' means read the traceback. Without one the report is useless."""
        try:
            raise TypeError("our bug")
        except TypeError as e:
            _, detail = _scan._classify(e)
        self.assertIn("Traceback", detail)

    def test_injected_checker_bug_reports_error_not_fail(self):
        real = _scan.check_rangeproofs.check_sig_bp_plus

        def broken(_tx_json):
            raise AttributeError("simulated defect inside the BP+ checker")

        _scan.check_rangeproofs.check_sig_bp_plus = broken
        try:
            status, detail = _scan.check_bp({})
        finally:
            _scan.check_rangeproofs.check_sig_bp_plus = real

        self.assertEqual(status, "error", "a checker defect must not read as a bad proof")
        self.assertIn("AttributeError", detail)

    def test_worst_status_wins_across_inputs(self):
        self.assertEqual(_scan._worst(["ok", "ok"]), "ok")
        self.assertEqual(_scan._worst(["ok", "skip"]), "skip")
        self.assertEqual(_scan._worst(["ok", "fail", "skip"]), "fail")
        self.assertEqual(_scan._worst(["ok", "fail", "error"]), "error")
        self.assertEqual(_scan._worst([]), "ok")


# ---------------------------------------------------------------------------
# 15. The balance and range-proof checks in isolation
# ---------------------------------------------------------------------------


class TestBalanceCheck(unittest.TestCase):
    """Σ pseudoOuts − Σ outPk − fee·H == 0 is the inflation invariant itself."""

    @classmethod
    def setUpClass(cls):
        cls.tx_json = _scan.tx_json_from_blob(built(1)["blob"])

    def test_balanced_transaction_passes(self):
        self.assertEqual(_scan.check_balance(self.tx_json)[0], "ok")

    def test_inflated_fee_fails(self):
        j = copy.deepcopy(self.tx_json)
        j["rct_signatures"]["txnFee"] += 1
        status, detail = _scan.check_balance(j)
        self.assertEqual(status, "fail")
        self.assertIn("pseudoOuts", detail)

    def test_missing_pseudo_outs_fails_rather_than_passing_vacuously(self):
        """rct type 7 carries pseudoOuts in rctsig_prunable, not rct_signatures.
        A check that looked only in the old place would pass every FCMP++ tx."""
        j = copy.deepcopy(self.tx_json)
        j["rctsig_prunable"]["pseudoOuts"] = []
        status, detail = _scan.check_balance(j)
        self.assertEqual(status, "fail")
        self.assertIn("no pseudoOuts", detail)

    def test_missing_out_commitments_is_a_failure_not_an_error(self):
        """A field the checker needs and cannot find is bad data, not our bug."""
        j = copy.deepcopy(self.tx_json)
        del j["rct_signatures"]["outPk"]
        self.assertEqual(_scan.check_balance(j)[0], "fail")


class TestRangeProofCheck(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tx_json = _scan.tx_json_from_blob(built(1)["blob"])

    def test_valid_bulletproof_passes(self):
        self.assertEqual(_scan.check_bp(self.tx_json)[0], "ok")

    def test_corrupt_bulletproof_fails(self):
        j = copy.deepcopy(self.tx_json)
        r1 = bytearray(bytes.fromhex(j["rctsig_prunable"]["bpp"][0]["r1"]))
        r1[0] ^= 0x01
        j["rctsig_prunable"]["bpp"][0]["r1"] = bytes(r1).hex()
        self.assertEqual(_scan.check_bp(j)[0], "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)
