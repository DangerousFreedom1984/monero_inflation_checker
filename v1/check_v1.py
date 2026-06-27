"""Verification of v1 (pre-RingCT) CryptoNote ring signatures and balances.

This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether
        (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.

This module is the verifier only. For a runnable demonstration of generating and
verifying a v1 ring signature see ``examples/example_v1_ring_signature.py``.
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

import misc_func
import settings_df25519
from df25519 import Scalar, Point
import df25519
from concurrent.futures import as_completed, ProcessPoolExecutor


def get_tx_prefix_hash(resp_json, resp_hex):
    """Return the tx-prefix hash that the v1 ring signatures are computed over."""
    signatures = resp_json["signatures"]
    sig = signatures[0]
    tx_prefix_raw = resp_hex.split(sig)[0]
    tx_prefix_hash = df25519.cn_fast_hash(tx_prefix_raw)
    return tx_prefix_hash.encode()


def get_signatures(resp_json, resp_hex, index):
    """Parse input ``index``'s ring signature into (ring_size, sigr, sigc)."""
    signatures = resp_json["signatures"]
    sig = signatures[index]

    n_ring_members = len(sig) // (64 * 2)
    sc, sr = [], []

    for i in range(0, int(2 * n_ring_members), 2):
        sc.append(df25519.Scalar(sig[int(i * 64) : int((i + 1) * 64)]))
        sr.append(df25519.Scalar(sig[int((i + 1) * 64) : int((i + 2) * 64)]))

    sigc = df25519.ScalarVector(sc)
    sigr = df25519.ScalarVector(sr)

    return n_ring_members, sigr, sigc


def get_key_image(resp_json, index):
    """Return the hex key image of input ``index``."""
    return resp_json["vin"][index]["key"]["k_image"]


def check_v1(resp_json, resp_hex, sig_ind, pubs, tx_prefix) -> bool:
    """Verify the v1 (pre-RingCT) ring signature for a single input.

    Returns True iff the ring signature for input ``sig_ind`` is valid.
    """
    pubs_count, sigr, sigc = get_signatures(resp_json, resp_hex, sig_ind)
    key_image = get_key_image(resp_json, sig_ind)

    return check_ring_signature(
        tx_prefix, key_image, df25519.PointVector(pubs[sig_ind]), pubs_count, sigr, sigc
    )


def ring_sig_correct(h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details):
    """Verify all v1 ring signatures, key images and the cleartext balance of a tx.

    Returns ``(str_ki, str_inp, "", str_commits)``: key-image checks, per-input ring
    signature results, an (unused) placeholder, and the balance check.
    """
    tx_prefix = get_tx_prefix_hash(resp_json, resp_hex)

    str_commits = check_balance(inputs, outputs, resp_json)

    str_ki = []
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        str_ki.append(misc_func.verify_ki(Iv))

    pubs, _ = misc_func.get_members_and_masks_in_rings(resp_json)

    y = []
    with ProcessPoolExecutor() as exe:
        for sig_ind in range(inputs):
            y.append(exe.submit(check_v1, resp_json, resp_hex, sig_ind, pubs, tx_prefix))

        str_inp = []
        for res in as_completed(y):
            try:
                str_inp.append(res.result())
            except Exception as exc:
                # Surface — never silently swallow — a verification failure.
                settings_df25519.logger_inflation.warning(
                    "block_height %s tx %s: v1 ring signature check raised: %r",
                    h,
                    txs[i_tx],
                    exc,
                )
                str_inp.append(False)

    return str_ki, str_inp, "", str_commits


def check_balance(inputs: int, outputs: int, resp_json: dict) -> bool:
    """Return True iff the sum of (cleartext) input amounts covers the outputs.

    For pre-RingCT (v1) transactions amounts are public, so inflation reduces to
    ``sum(vin) >= sum(vout)``. A False result means the outputs exceed the inputs.
    """
    # Pre-RingCT (v1) amounts are cleartext integers; 
    Cin = 0
    Cout = 0

    for sig_ind in range(inputs):
        Cin += resp_json["vin"][sig_ind]["key"]["amount"]

    for sig_ind in range(outputs):
        Cout += resp_json["vout"][sig_ind]["amount"]

    return Cin >= Cout


def check_ring_signature(prefix, key_image, pubs, pubs_count, sigr, sigc) -> bool:
    """Verify a CryptoNote v1 ring signature against ``prefix`` and ``key_image``.

    Recomputes the per-member L_i/R_i points and checks that the challenge sum equals
    the Fiat-Shamir hash of (prefix, all L_i, R_i). Returns True iff they match.
    """
    Li = [Scalar(0) for _ in range(pubs_count)]
    Ri = [Scalar(0) for _ in range(pubs_count)]

    summ = Scalar(0)
    for ii in range(pubs_count):
        Li[ii] = sigr[ii] * df25519.G + sigc[ii] * pubs[ii]
        Ri[ii] = sigr[ii] * df25519.hash_to_point(str(pubs[ii])) + sigc[ii] * Point(key_image)
        summ += sigc[ii]

    buf = prefix.decode()
    for ii in range(pubs_count):
        buf += str(Li[ii])
        buf += str(Ri[ii])

    h = df25519.hash_to_scalar(buf)
    res = summ - h

    return res == Scalar(0)
