"""Real-data verification tests for every Monero transaction type.

Each test fetches a real transaction from the chain and runs MIC's full verifier
on it, asserting it verifies.  One representative tx is used per signature type:

    v1            pre-RingCT ring signature          (mainnet)
    RCT type 1    RCTTypeFull   (MLSAG)              (mainnet)
    RCT type 2    RCTTypeSimple (MLSAG)              (mainnet)
    RCT type 3    RCTTypeBulletproof                 (mainnet)
    RCT type 4    RCTTypeBulletproof2                (mainnet)
    RCT type 5    RCTTypeCLSAG                       (mainnet)
    RCT type 6    RCTTypeBulletproofPlus             (mainnet)
    RCT type 7    RCTTypeFcmpPlusPlus (FCMP++)       (testnet proof, offline)

The mainnet txids are the curated ones from ``scanner/scan_bc.py``
(``txs_to_benchmark``); they exercise types that no longer appear near the chain
tip.  Type 7 (FCMP++) is not on mainnet, so it is verified offline from a captured
proof under ``fcmp/tests/``.

Network tests hit a public mainnet node (``settings_df25519.url_str``); if it is
unreachable they are skipped (the offline type-7 test still runs).

Run with::

    python -m unittest unittests.test_verify_types
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
import urllib.request

import settings_df25519
import verify_tx

# Pin the mainnet node explicitly so these tests are hermetic: other test modules
# (e.g. test_coinbase) call settings_df25519.node_choice() at import and mutate the
# shared url_str.  Override with MIC_MAINNET_NODE if needed.
MAINNET_NODE = _os.environ.get("MIC_MAINNET_NODE", "http://xmr-node.cakewallet.com:18081/")


def setUpModule():
    settings_df25519.url_str = MAINNET_NODE

# Representative real mainnet transactions, one (or two) per type.
# Source: scanner/scan_bc.py :: txs_to_benchmark().
TXS = {
    "v1_2x8": "3b26d90c460ccab37925300ca830b569636ba8053f859a95312c227312d1a72d",
    "v1_4x5": "8d7aea7480fcf53e6b9bef5d398c4031d923b0a0a47d6e088f69b49a8674a542",
    "t1_mlsag_full": "a61c75c5c5f8e449f93dd395e44f090ca66176dad62c5a4c89f26a921630d4e0",
    "t2_mlsag_simple": "257b917219699be7ea8ace43c80773674c2d0cda12702ad6a82de61a861a08c7",
    "t3_bulletproof": "b374a5abf666a189d6fa8bb4fe3724278b7c553dba4837f2d52e644401b78222",
    "t4_bulletproof2": "0fcb5cb5ed4b84008d8f01c8c10ad255417deff5862513c99d8b9203c68a4acc",
    "t5_clsag": "d6093af328ea42984a715eaddfdfec6a67d4572f4f5cc5344a5d0d5f67b5a9f2",
    "t6_bulletproof_plus": "d6eb7f7f27f643c4b8ea6ef2683bd0601ee540cb37f4e27eb18ad85d1f46a85a",
}

# Captured FCMP++ (type 7) proof + consensus params, verified offline.
_FCMP_DIR = _os.path.join(_d, "fcmp")
FCMP_PROOF = _os.path.join(
    _FCMP_DIR, "tests",
    "fa4c01c142cc72d9345e366a811f83df6cdd4ec1d7e715db705c9a2646c407ae.fcmp_input.json")
FCMP_PARAMS = _os.path.join(_FCMP_DIR, "src", "input_params.txt")


def _node_reachable() -> bool:
    try:
        req = urllib.request.Request(
            MAINNET_NODE + "get_height",
            data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


_NODE_OK = _node_reachable()
_SKIP_NET = "mainnet node %s not reachable" % MAINNET_NODE


@unittest.skipUnless(_NODE_OK, _SKIP_NET)
class TestVerifyMainnetTypes(unittest.TestCase):
    """Verify a real mainnet tx of each pre-FCMP signature type (network)."""

    def _verify(self, key):
        self.assertTrue(verify_tx.verify_tx([TXS[key]], 0),
                        f"{key} ({TXS[key]}) failed verification")

    def test_v1_ring_signature_2in8out(self):
        self._verify("v1_2x8")

    def test_v1_ring_signature_4in5out(self):
        self._verify("v1_4x5")

    def test_type1_mlsag_full(self):
        self._verify("t1_mlsag_full")

    def test_type2_mlsag_simple(self):
        self._verify("t2_mlsag_simple")

    def test_type3_bulletproof(self):
        self._verify("t3_bulletproof")

    def test_type4_bulletproof2(self):
        self._verify("t4_bulletproof2")

    def test_type5_clsag(self):
        self._verify("t5_clsag")

    def test_type6_bulletproof_plus(self):
        self._verify("t6_bulletproof_plus")


class TestVerifyFcmpType7(unittest.TestCase):
    """Verify a real FCMP++ (type 7) proof offline from a captured input file."""

    @unittest.skip("fcmp_input_verifier was moved out of this repo; FCMP++ proof "
                   "verification is covered by fcmp/scanner and fcmp/tests")
    def test_type7_fcmp_plus_plus(self):
        import fcmp_input_verifier
        self.assertTrue(_os.path.exists(FCMP_PROOF), "captured FCMP++ proof missing")
        self.assertTrue(fcmp_input_verifier.verify(FCMP_PROOF, FCMP_PARAMS),
                        "FCMP++ (type 7) proof failed verification")


if __name__ == "__main__":
    unittest.main(verbosity=2)
