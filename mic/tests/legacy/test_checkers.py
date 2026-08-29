"""Offline unit tests for the proof checkers (no daemon / network required).

These exercise the parts of the verification path that are deterministic and
node-independent:

* ``check_v1.check_balance``: the v1 (pre-RingCT) inflation check itself, on a
  known-good (balanced) and a known-bad (over-issuing) transaction.
* ``df25519`` Scalar/Point construction: must raise ``TypeError`` on malformed
  input (guards the narrowed ``except Exception`` handlers in df25519.py).

Run with::

    python -m unittest mic.tests.legacy.test_checkers
"""


import unittest

from mic.v1 import check_v1
from mic.common import df25519
def _tx(vin_amounts, vout_amounts):
    """Build a minimal resp_json shaped like a daemon's decoded v1 transaction."""
    return {
        "vin": [{"key": {"amount": a}} for a in vin_amounts],
        "vout": [{"amount": a} for a in vout_amounts],
    }


class TestCheckBalance(unittest.TestCase):
    def test_balanced_tx_passes(self):
        # Inputs cover outputs (remainder is the fee): no inflation.
        resp = _tx([1000, 500], [1200, 200])
        self.assertTrue(check_v1.check_balance(2, 2, resp))

    def test_exact_balance_passes(self):
        resp = _tx([1000], [1000])
        self.assertTrue(check_v1.check_balance(1, 1, resp))

    def test_inflation_is_detected(self):
        # Outputs exceed inputs => money created from nothing => must fail.
        resp = _tx([1000], [600, 600])
        self.assertFalse(check_v1.check_balance(1, 2, resp))

    def test_large_atomic_amounts_are_exact(self):
        # Differ by 1 atomic unit near 2**63. Float arithmetic would lose this.
        big = 9_223_372_036_854_775_807  # 2**63 - 1
        self.assertTrue(check_v1.check_balance(1, 1, _tx([big], [big - 1])))
        self.assertFalse(check_v1.check_balance(1, 1, _tx([big - 1], [big])))


class TestDf25519BadInput(unittest.TestCase):
    def test_scalar_rejects_non_hex(self):
        with self.assertRaises(TypeError):
            df25519.Scalar("not-hex-zzzz")

    def test_point_rejects_non_hex(self):
        with self.assertRaises(TypeError):
            df25519.Point("not-hex-zzzz")

    def test_scalar_rejects_unsupported_type(self):
        with self.assertRaises(TypeError):
            df25519.Scalar(3.14)


if __name__ == "__main__":
    unittest.main(verbosity=2)
