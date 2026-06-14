#!/usr/bin/env python3
"""extract_fields.py — Parse and explain every field in proofs/proof1.json.

proof1.json is a raw Monero transaction (RPC format). The FCMP++ proof itself
lives inside rctsig_prunable.fcmp_pp as a concatenated hex string.

Usage:
    cd ccs/python && python extract_fields.py [path/to/proof.json]
"""

import json
import sys
import os

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "proofs", "proof1.json")


def _proof_size(inputs: int, layers: int) -> int:
    C1_LEAVES = 97; C1_BRANCH = 52; C2_PER = 32
    C1_TARGET = 256; C2_TARGET = 128; COMMIT_LEN = 128; CP = 4
    non_leaves_c1 = (layers - 1) // 2
    c1_rows = inputs * (C1_LEAVES + non_leaves_c1 * C1_BRANCH)
    c2_rows = inputs * max((layers // 2) * C2_PER, 1)
    c1_pad = max(1 << (c1_rows - 1).bit_length() if c1_rows > 1 else 1, C1_TARGET)
    c2_pad = max(1 << (c2_rows - 1).bit_length() if c2_rows > 1 else 1, C2_TARGET)
    pe = 16
    r = 1
    while r < c1_pad: r <<= 1; pe += 2
    r = 1
    while r < c2_pad: r <<= 1; pe += 2
    c1_root = layers % 2; c2_root = 1 - c1_root
    c1_b = inputs * (layers // 2) + c1_root
    c2_b = inputs * ((layers // 2) - c2_root) + c2_root
    c1_w = inputs * (2 + 4 * CP) + inputs * ((layers - 1) // 2) * CP
    c2_w = inputs * (layers // 2) * CP
    c1c = c1_b + -(-c1_w * COMMIT_LEN // c1_pad)
    ni1 = 2 + 2 * (c1c // 2); t1 = 2 * (1 + ni1 + 1) - 2
    c2c = c2_b + -(-c2_w * COMMIT_LEN // c2_pad)
    ni2 = 2 + 2 * (c2c // 2); t2 = 2 * (1 + ni2 + 1) - 2
    pe += c1c + t1 + c2c + t2
    return 32 * pe + 64


def extract(path: str):
    with open(path) as f:
        tx = json.load(f)

    print("=" * 72)
    print("MONERO TRANSACTION — FIELD BREAKDOWN")
    print(f"Source: {path}")
    print("=" * 72)

    # ── Top-level fields ─────────────────────────────────────────────────────
    print("\n── Transaction header ──")
    print(f"  version      : {tx['version']}  (format version)")
    print(f"  unlock_time  : {tx['unlock_time']}  (0 = no time-lock)")

    # ── Inputs ───────────────────────────────────────────────────────────────
    print(f"\n── Inputs  ({len(tx['vin'])} total) ──")
    for idx, inp in enumerate(tx["vin"]):
        key = inp["key"]
        print(f"  vin[{idx}]:")
        print(f"    amount      : {key['amount']}")
        print(f"    key_offsets : {key['key_offsets']}  (ring member indices; empty = FCMP++ single-input)")
        print(f"    k_image     : {key['k_image']}")
        print(f"                  (32-byte key image; unique per spent output)")

    # ── Outputs ──────────────────────────────────────────────────────────────
    print(f"\n── Outputs  ({len(tx['vout'])} total) ──")
    for idx, out in enumerate(tx["vout"]):
        print(f"  vout[{idx}]:")
        print(f"    amount   : {out['amount']}  (0 = confidential)")
        target = out["target"]
        if "carrot_v1" in target:
            cv = target["carrot_v1"]
            print(f"    type     : carrot_v1  (Monero Seraphis-era output format)")
            print(f"    key      : {cv['key']}  (one-time public key)")
            print(f"    view_tag : {cv['view_tag']}  (3-byte scanning shortcut)")
            print(f"    enc_janus: {cv['encrypted_janus_anchor']}  (16-byte janus anchor, encrypted)")

    # ── Extra ─────────────────────────────────────────────────────────────────
    extra = tx.get("extra", [])
    print(f"\n── extra  ({len(extra)} bytes) ──")
    print(f"  raw: {bytes(extra).hex()}")
    print(f"  (may contain tx public key, additional keys, payment ID, nonce)")

    # ── RingCT signatures ────────────────────────────────────────────────────
    rct = tx["rct_signatures"]
    print(f"\n── rct_signatures ──")
    print(f"  type    : {rct['type']}  (7 = FCMP++ transaction type)")
    print(f"  txnFee  : {rct['txnFee']}  (fee in atomic units)")
    print(f"  ecdhInfo:")
    for i, e in enumerate(rct["ecdhInfo"]):
        print(f"    [{i}] amount: {e['amount']}  (encrypted confidential amount)")
    print(f"  outPk:")
    for i, pk in enumerate(rct["outPk"]):
        print(f"    [{i}]: {pk}  (output Pedersen commitment, compressed point)")

    # ── Prunable ─────────────────────────────────────────────────────────────
    prunable = tx["rctsig_prunable"]
    print(f"\n── rctsig_prunable ──")
    print(f"  nbp              : {prunable['nbp']}  (number of Bulletproof+ range proofs)")

    # Bulletproof+
    for i, bp in enumerate(prunable["bpp"]):
        print(f"\n  bpp[{i}]  (Bulletproof+ range proof for output amounts):")
        for key in ["A", "A1", "B", "r1", "s1", "d1"]:
            print(f"    {key:4s}: {bp[key]}")
        print(f"    L  : {len(bp['L'])} elements  ({', '.join(bp['L'][:2])}...)")
        print(f"    R  : {len(bp['R'])} elements  ({', '.join(bp['R'][:2])}...)")

    print(f"\n  reference_block  : {prunable['reference_block']}")
    print(f"  (block height whose UTXO tree root anchors the FCMP++ proof)")

    n_tree_layers = prunable["n_tree_layers"]
    print(f"\n  n_tree_layers    : {n_tree_layers}")
    fcmp_layers = n_tree_layers * 2
    print(f"  (FCMP layers parameter = n_tree_layers × 2 = {fcmp_layers})")
    print(f"  (even layers → root on C2/Helios; odd → root on C1/Selene)")

    print(f"\n  pseudoOuts:")
    for i, po in enumerate(prunable["pseudoOuts"]):
        print(f"    [{i}]: {po}  (pseudo-output commitment for input #{i})")

    # ── FCMP++ proof bytes ────────────────────────────────────────────────────
    fcmp_pp_hex = prunable["fcmp_pp"]
    fcmp_bytes = bytes.fromhex(fcmp_pp_hex)
    total = len(fcmp_bytes)
    pok = fcmp_bytes[-64:]
    proof_body = fcmp_bytes[:-64]
    n_inputs = len(tx["vin"])

    expected = _proof_size(n_inputs, fcmp_layers)

    print(f"\n── rctsig_prunable.fcmp_pp  (the FCMP++ proof) ──")
    print(f"  total bytes       : {total}")
    print(f"  expected size     : {expected}  (proof_size(inputs={n_inputs}, layers={fcmp_layers}))")
    print(f"  size matches      : {total == expected}")
    print(f"\n  Layout: [proof_body ({total - 64} bytes)] [root_blind_pok (64 bytes)]")

    print(f"\n  root_blind_pok (bytes {total-64}..{total}):")
    print(f"    R (bytes 0-31) : {pok[:32].hex()}")
    print(f"    s (bytes 32-63): {pok[32:].hex()}")
    print(f"    (Schnorr PoK proving knowledge of the tree root blinding factor)")
    print(f"    R = r·H  (nonce commitment on C1 or C2 generator H)")
    print(f"    s = r + c·blind  (response, c = Fiat-Shamir challenge)")

    print(f"\n  proof_body — first 5 × 32-byte elements (GBP commitment points):")
    for i in range(min(5, len(proof_body) // 32)):
        el = proof_body[i * 32:(i + 1) * 32].hex()
        print(f"    element[{i}]: {el}")
    print(f"  ... ({len(proof_body) // 32} elements total in the GBP proof)")

    print(f"\n  Full verification requires (NOT stored in fcmp_pp):")
    print(f"    • Tree root at block {prunable['reference_block']} (from blockchain)")
    print(f"    • Per-input (O_tilde, I_tilde, R, C_tilde) tuples (from wallet+chain)")
    print(f"    • FcmpParams (public parameters; consensus-fixed for mainnet)")
    print()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH
    extract(path)
