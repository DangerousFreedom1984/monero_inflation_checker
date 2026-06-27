"""Proof-creation tests: build a proof with MIC's prover and verify it round-trips.

These are fully offline (no daemon): they construct commitments to known amounts,
generate a Bulletproof+ range proof with ``check_rangeproofs.prove_bp_plus``, and
verify it with ``check_rangeproofs.check_bp_plus`` (the same verifier the on-chain
type 5/6 path uses).  A tampered amount must fail, proving the check is meaningful.

Run with::

    python -m unittest unittests.test_create_proof
"""

# --- MIC path bootstrap: locate package root and configure sys.path ---
import os as _os, sys as _sys

_d = _os.path.dirname(_os.path.abspath(__file__))
while _d != _os.path.dirname(_d):
    if _os.path.exists(_os.path.join(_d, "mic_paths.py")):
        if _d not in _sys.path:
            _sys.path.insert(0, _d)
        break
    _d = _os.path.dirname(_d)
import mic_paths  # noqa: E402,F401  (configures sys.path for component dirs)

# --- end MIC path bootstrap ---

import unittest

import df25519
from df25519 import Scalar, random_scalar
import check_rangeproofs as cr


def _proof_as_list(bp):
    """The list shape check_bp_plus expects (matches get_vars_bp_plus's output)."""
    return [bp.V, bp.A, bp.A1, bp.B, bp.r1, bp.s1, bp.d1, bp.L, bp.R]


class TestBulletproofPlusRoundTrip(unittest.TestCase):
    def test_single_output_proof_verifies(self):
        amounts = [Scalar(12345)]
        masks = [random_scalar()]
        bp = cr.prove_bp_plus(amounts, masks)
        self.assertTrue(cr.check_bp_plus([_proof_as_list(bp)]),
                        "freshly created BP+ proof must verify")

    def test_multi_output_proof_verifies(self):
        # Two outputs, including a large in-range value (2**40 + 7).
        amounts = [Scalar(2 ** 40 + 7), Scalar(0)]
        masks = [random_scalar(), random_scalar()]
        bp = cr.prove_bp_plus(amounts, masks)
        self.assertTrue(cr.check_bp_plus([_proof_as_list(bp)]),
                        "multi-output BP+ proof must verify")

    def test_tampered_commitment_fails(self):
        # Create a valid proof, then corrupt the committed value V.  The proof
        # must no longer verify, otherwise the check is vacuous.
        amounts = [Scalar(99)]
        masks = [random_scalar()]
        bp = cr.prove_bp_plus(amounts, masks)
        proof = _proof_as_list(bp)
        # bump the commitment by H (i.e. claim amount+1) -> proof must be rejected
        proof[0] = df25519.PointVector([bp.V[0] + df25519.H * df25519.inv8])
        self.assertFalse(cr.check_bp_plus([proof]),
                         "BP+ proof must fail against a tampered commitment")


if __name__ == "__main__":
    unittest.main(verbosity=2)
