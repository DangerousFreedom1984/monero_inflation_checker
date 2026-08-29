#!/usr/bin/env python3
"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

FCMP++ testnet chain scanning

Walks a Monero (testnet/stressnet) chain block by block and fully verifies every
FCMP++ transaction in it. Everything is checked by this repo's own pure-Python
code. 

    python fcmp_tool.py scan --start-height 3039000
    python fcmp_tool.py scan --record dump.json      # save every RPC response
    python fcmp_tool.py scan --replay dump.json      # re-run offline from a dump

--record / --replay make a scan reproducible without the node: the recorder
saves each get_block / get_transactions response keyed by its arguments, and the
replayer serves them back.

Two log files are written under logs/ in the repo root:
    scan.log        JSON-lines, one event per line, machine-parseable
    scan_stats.log  a human-readable stats block after each block

This tool checks four things:

  membership  the FCMP++ curve-tree membership proof: the spent output exists in
              the tree whose root the reference block commits to, and its blinded
              tuple (O~, I~, R, C~) is a re-randomization of a real leaf. Verified
              by Fcmp.verify, which rebuilds the whole arithmetic circuit from
              mic/fcmp/gadgets.py and checks the Generalized-Bulletproofs proof
              against it.
  sal         per input, the Spend-Authorization & Linkability proof: knowledge of
              the spend key behind O~, bound to this exact transaction's
              signable_tx_hash, and emitting the key image in vin[i].
  bp          the Bulletproof+ range proof over the output commitments 
  balance     Sum pseudoOuts - Sum outPk - fee*H == 0, the inflation invariant itself.

`python fcmp_tool.py verify-tx` reaches verify_tx() here for a single
transaction. The `scan` subcommand reaches run().
"""

import argparse
import json
import logging
import time
import traceback
import urllib.error
import urllib.request
from typing import Optional

from Crypto.Hash import keccak

from mic import paths

from mic.common import df25519
from mic.common.df25519 import Point, Scalar

from mic.fcmp import PARAMS_FILE
from mic.fcmp.circuit import CurveSpec, GeneratorTable, OC_PARAMS, C1_PARAMS, C2_PARAMS
from mic.fcmp.curve import (
    HELIOS,
    HELIOS_B,
    SELENE,
    SELENE_B,
    WEI25519,
    WPoint,
    helios_from_bytes,
    oc_from_bytes,
    selene_from_bytes,
)
from mic.fcmp.field import HeliosField, SeleneField
from mic.fcmp.gbp import Generators
from mic.fcmp.proof import Fcmp, FcmpParams
from mic.fcmp import sal as _sal

from mic.rangeproofs import check_rangeproofs
from mic.txlib import serialize as _serialize

DEFAULT_NODE = "http://localhost:28081"

# ── Blob layout (fcmp_pp_proof_from_parts_v1 in fcmp_pp_types.cpp) ────────────
#   per input:  O_tilde(32) | I_tilde(32) | R(32) | SAL_proof(12×32 = 384)
#   then:       membership proof body
#   last 64:    root_blind_PoK
_INPUT_TUPLE = 3 * 32  # 96 bytes: O_tilde + I_tilde + R
SAL_SIZE = _sal.SAL.SIZE  # 384 bytes, from the proof type itself
_PER_INPUT = _INPUT_TUPLE + SAL_SIZE  # 480 bytes per input
_POK_SIZE = 64  # root_blind Schnorr PoK

RCT_TYPE_FCMP = 7  # rct::RCTTypeFcmpPlusPlus

ALL_CHECKS = ("membership", "sal", "bp", "balance")

# reference_block in a TX is a LOCK INDEX, not a block height: the root for lock
# index K lives in the block at height K - 8.
_SPENDABLE_AGE = 10
LOCK_OFFSET = _SPENDABLE_AGE - 2  # = 8


# --------------------------------------------------------------------------- #
#  FcmpParams loading
# --------------------------------------------------------------------------- #


def _parse_kv(path: str) -> dict:
    d: dict = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k in d:
                if not isinstance(d[k], list):
                    d[k] = [d[k]]
                d[k].append(v)
            else:
                d[k] = v
    return d


def _le(hex_str: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), "little")


def _collect(kv: dict, prefix: str) -> list:
    """Values of prefix[0], prefix[1], … in index order, up to the first gap."""
    out = []
    while True:
        v = kv.get(f"{prefix}[{len(out)}]")
        if v is None:
            return out
        out.append(v)


def load_params(params_path: str = PARAMS_FILE) -> FcmpParams:
    """Decode the consensus generators from input_params.txt into an FcmpParams."""
    kv = _parse_kv(params_path)

    id_c1 = WPoint.identity(SeleneField, SELENE_B)
    id_c2 = WPoint.identity(HeliosField, HELIOS_B)

    def _sel(key):
        return selene_from_bytes(bytes.fromhex(kv[key]))

    def _hel(key):
        return helios_from_bytes(bytes.fromhex(kv[key]))

    def _gens(prefix, decode, identity, initial):
        g_hex = _collect(kv, f"{prefix}.g_bold")
        h_hex = _collect(kv, f"{prefix}.h_bold")
        capacity = min(len(g_hex), len(h_hex))
        initial = min(initial, capacity)

        def extend(start, stop):
            return (
                [decode(bytes.fromhex(x)) for x in g_hex[start:stop]],
                [decode(bytes.fromhex(x)) for x in h_hex[start:stop]],
            )

        g_bold, h_bold = extend(0, initial)
        return Generators(
            decode(bytes.fromhex(kv[f"{prefix}.g"])),
            decode(bytes.fromhex(kv[f"{prefix}.h"])),
            g_bold,
            h_bold,
            identity,
            extend=extend,
            capacity=capacity,
        )

    c1_gens = _gens("curve_1_generators", selene_from_bytes, id_c1, 512)
    c2_gens = _gens("curve_2_generators", helios_from_bytes, id_c2, 256)

    OC_SPEC = CurveSpec.for_curve(WEI25519)
    C1_SPEC = CurveSpec.for_curve(SELENE)
    C2_SPEC = CurveSpec.for_curve(HELIOS)

    G_table = GeneratorTable(
        OC_SPEC,
        HeliosField(_le(kv["G_table[0].x"])),
        HeliosField(_le(kv["G_table[0].y"])),
        OC_PARAMS.scalar_bits,
    )
    T_table = GeneratorTable(
        OC_SPEC,
        HeliosField(_le(kv["T_table[0].x"])),
        HeliosField(_le(kv["T_table[0].y"])),
        OC_PARAMS.scalar_bits,
    )
    U_table = GeneratorTable(
        OC_SPEC,
        HeliosField(_le(kv["U_table[0].x"])),
        HeliosField(_le(kv["U_table[0].y"])),
        OC_PARAMS.scalar_bits,
    )
    V_table = GeneratorTable(
        OC_SPEC,
        HeliosField(_le(kv["V_table[0].x"])),
        HeliosField(_le(kv["V_table[0].y"])),
        OC_PARAMS.scalar_bits,
    )

    H_1_table = GeneratorTable(
        C1_SPEC,
        SeleneField(_le(kv["H_1_table[0].x"])),
        SeleneField(_le(kv["H_1_table[0].y"])),
        C1_PARAMS.scalar_bits,
    )
    H_2_table = GeneratorTable(
        C2_SPEC,
        HeliosField(_le(kv["H_2_table[0].x"])),
        HeliosField(_le(kv["H_2_table[0].y"])),
        C2_PARAMS.scalar_bits,
    )

    return FcmpParams(
        curve_1_generators=c1_gens,
        curve_2_generators=c2_gens,
        curve_1_hash_init=_sel("curve_1_hash_init"),
        curve_2_hash_init=_hel("curve_2_hash_init"),
        G_table=G_table,
        T_table=T_table,
        U_table=U_table,
        V_table=V_table,
        H_1_table=H_1_table,
        H_2_table=H_2_table,
    )


# --------------------------------------------------------------------------- #
#  node access (live / recording / replay)
# --------------------------------------------------------------------------- #


class NodeRPC:
    """A read-only Monero JSON-RPC client. Works against a restricted endpoint.

    get_transactions asks for prune=false because the SAL check needs the raw
    transaction blob, not just the decoded JSON.
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        self._rpc = base_url.rstrip("/") + "/json_rpc"
        self._base = base_url.rstrip("/")
        self.timeout = timeout

    def _json_rpc(self, method: str, params: dict | None = None) -> dict:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "0",
                "method": method,
                "params": params or {},
            }
        ).encode()
        req = urllib.request.Request(
            self._rpc,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            result = json.loads(resp.read())
        if "error" in result:
            raise RuntimeError(f"RPC {method}: {result['error']}")
        return result["result"]

    def _post(self, endpoint: str, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._base}/{endpoint}",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def get_block_count(self) -> int:
        return self._json_rpc("get_block_count")["count"]

    def get_block(self, height: int) -> dict:
        return self._json_rpc("get_block", {"height": height})

    def get_transactions(self, tx_hashes) -> dict:
        return self._post(
            "get_transactions",
            {"txs_hashes": list(tx_hashes), "decode_as_json": True, "prune": False},
        )


class RecordingRPC(NodeRPC):
    """Live node access that also saves every response to a dump."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls = {}

    def get_block(self, height):
        r = super().get_block(height)
        self.calls[f"get_block:{height}"] = r
        return r

    def get_transactions(self, tx_hashes):
        key = "get_transactions:" + ",".join(sorted(tx_hashes))
        r = super().get_transactions(tx_hashes)
        self.calls[key] = r
        return r

    def get_block_count(self):
        r = super().get_block_count()
        self.calls["get_block_count"] = r
        return r

    def save(self, path):
        with open(path, "w") as f:
            json.dump({"node": self._base, "calls": self.calls}, f)


class ReplayRPC:
    """Serves recorded responses from a dump. Never touches the network."""

    def __init__(self, dump_path):
        with open(dump_path) as f:
            d = json.load(f)
        self.calls = d["calls"]
        self._base = d.get("node", "replay://" + dump_path)

    def _get(self, key):
        if key not in self.calls:
            raise KeyError(f"offline dump has no recorded response for {key!r}")
        return self.calls[key]

    def get_block(self, height):
        return self._get(f"get_block:{height}")

    def get_transactions(self, tx_hashes):
        return self._get("get_transactions:" + ",".join(sorted(tx_hashes)))

    def get_block_count(self):
        return self._get("get_block_count")


# --------------------------------------------------------------------------- #
#  transaction parsing
# --------------------------------------------------------------------------- #


def _keccak(b: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(b)
    return k.digest()


def signable_tx_hash(tx) -> bytes:
    """keccak(keccak(prefix) || keccak(rct base)): what the SAL proof signs."""
    return _keccak(
        _keccak(_serialize.serialize_prefix(tx)) + _keccak(_serialize.serialize_rct_base(tx))
    )


def tx_json_from_blob(blob: bytes) -> dict:
    """Re-derive the daemon's decoded-JSON shape from a raw transaction blob.

    Lets a locally-produced transaction, or a blob saved from anywhere, run
    through the same verification stack a chain scan uses, with no node in the
    loop. Only the fields the checks read are populated.
    """
    tx = _serialize.parse_tx(blob)
    return {
        "vin": [{"key": {"k_image": v.k_image.hex(), "amount": v.amount}} for v in tx.vin],
        "vout": [{"amount": o.amount, "target": {"key": o.key.hex()}} for o in tx.vout],
        "rct_signatures": {
            "type": tx.rct_type,
            "txnFee": tx.txnFee,
            "ecdhInfo": [{"amount": e.hex()} for e in tx.ecdhInfo],
            "outPk": [p.hex() for p in tx.outPk],
        },
        "rctsig_prunable": {
            "nbp": len(tx.bpp),
            "bpp": [
                {
                    "A": b.A.hex(), "A1": b.A1.hex(), "B": b.B.hex(),
                    "r1": b.r1.hex(), "s1": b.s1.hex(), "d1": b.d1.hex(),
                    "L": [x.hex() for x in b.L],
                    "R": [x.hex() for x in b.R],
                }
                for b in tx.bpp
            ],
            "reference_block": tx.reference_block,
            "n_tree_layers": tx.n_tree_layers,
            "fcmp_pp": tx.fcmp_pp.hex(),
            "pseudoOuts": [p.hex() for p in tx.pseudoOuts],
        },
    }


def _oc(hex_str: str):
    pt = oc_from_bytes(bytes.fromhex(hex_str))
    if pt is None:
        raise ValueError(f"invalid OC point: {hex_str[:16]}…")
    return pt


def parse_fcmp_tx(tx_json: dict) -> Optional[dict]:
    """Extract FCMP++ verification inputs from a decoded transaction JSON.

    Returns None for non-FCMP++ TXs.  Raises ValueError on malformed data.
    """
    rct = tx_json.get("rct_signatures", {})
    if rct.get("type") != RCT_TYPE_FCMP:
        return None

    prunable = tx_json.get("rctsig_prunable", {})
    n_tree_layers = int(prunable["n_tree_layers"])
    reference_block = int(prunable["reference_block"])
    fcmp_pp_hex = prunable["fcmp_pp"]
    pseudo_outs = prunable["pseudoOuts"]

    n_inputs = len(tx_json.get("vin", []))
    if n_inputs == 0:
        raise ValueError("TX has no vin entries")

    fcmp_bytes = bytes.fromhex(fcmp_pp_hex)
    min_len = n_inputs * _PER_INPUT + _POK_SIZE
    if len(fcmp_bytes) < min_len:
        raise ValueError(
            f"fcmp_pp too short: {len(fcmp_bytes)} bytes, need ≥ {min_len} "
            f"for {n_inputs} input(s)"
        )

    inputs = []
    for i in range(n_inputs):
        base = i * _PER_INPUT
        inputs.append(
            {
                "O_tilde": _oc(fcmp_bytes[base : base + 32].hex()),
                "I_tilde": _oc(fcmp_bytes[base + 32 : base + 64].hex()),
                "R": _oc(fcmp_bytes[base + 64 : base + 96].hex()),
                "C_tilde": _oc(pseudo_outs[i]),
            }
        )

    return {
        "n_tree_layers": n_tree_layers,
        "reference_block": reference_block,
        "proof_bytes": fcmp_bytes[n_inputs * _PER_INPUT : -_POK_SIZE],
        "root_blind_pok": fcmp_bytes[-_POK_SIZE:],
        "inputs": inputs,
        "n_inputs": n_inputs,
        "proof_bytes_len": len(fcmp_bytes),
    }


# --------------------------------------------------------------------------- #
#  the four checks
# --------------------------------------------------------------------------- #

# A checker that reports its own bugs as failed proofs raises false inflation
# alarms, and a false alarm is indistinguishable from the real thing until
# someone reads the traceback. So separate the two.
#
# ValueError is this codebase's signal for "this data is not valid". EOFError,
# IndexError and KeyError come out of parsing a malformed blob. Anything else
# (TypeError, AttributeError, RuntimeError, ...) is a defect here, not evidence
# about the transaction.
_INVALID = (ValueError, EOFError, IndexError, KeyError)


def _classify(e: BaseException) -> tuple:
    """Return ('fail'|'error', detail) for an exception raised by a check."""
    if isinstance(e, _INVALID):
        return "fail", f"{type(e).__name__}: {e}"
    return "error", f"{type(e).__name__}: {e}\n{traceback.format_exc()}"


_SEVERITY = {"ok": 0, "skip": 1, "fail": 2, "error": 3}


def _worst(statuses) -> str:
    """The most severe status in a group, e.g. across a transaction's inputs."""
    return max(statuses, key=lambda s: _SEVERITY[s], default="ok")


def verify_membership_proof(parsed: dict, tree_root_bytes: bytes, params: FcmpParams) -> float:
    """Run Fcmp.verify() for one parsed FCMP++ TX.  Returns elapsed seconds.

    Raises on verification failure or any exception inside Fcmp.verify().
    """
    layers = parsed["n_tree_layers"]  # not doubled. Fcmp.verify() takes n_tree_layers directly
    is_c1 = (layers % 2) == 1  # odd → root on C1/Selene, even → C2/Helios

    counter = [0]

    def rng_fn():
        counter[0] += 1
        return SeleneField(counter[0])

    v1 = Generators.new_batch_verifier(HeliosField)
    v2 = Generators.new_batch_verifier(SeleneField)

    t0 = time.perf_counter()
    Fcmp.verify(
        proof=parsed["proof_bytes"],
        root_blind_pok=parsed["root_blind_pok"],
        params=params,
        is_c1=is_c1,
        tree_root_bytes=tree_root_bytes,
        layers=layers,
        inputs=parsed["inputs"],
        verifier_1=v1,
        verifier_2=v2,
        rng_fn=rng_fn,
    )
    ok1 = params.curve_1_generators.verify(v1)
    ok2 = params.curve_2_generators.verify(v2)
    elapsed = time.perf_counter() - t0

    if not (ok1 and ok2):
        raise ValueError(
            f"batch_verifier failed: C1={'ok' if ok1 else 'FAIL'} " f"C2={'ok' if ok2 else 'FAIL'}"
        )
    return elapsed


def check_membership(parsed: dict, tree_root_bytes: bytes, params) -> tuple:
    """Run Fcmp.verify for the whole transaction. Returns (status, detail, seconds)."""
    t0 = time.perf_counter()
    try:
        elapsed = verify_membership_proof(parsed, tree_root_bytes, params)
        return "ok", "accepted", elapsed
    except Exception as e:
        status, detail = _classify(e)
        return status, detail, time.perf_counter() - t0


def check_sal(tx, fcmp_bytes: bytes, n_inputs: int) -> tuple:
    """Verify every input's SAL proof against the tx's own signable hash.

    The membership proof reads the same per-input region through parse_fcmp_tx.
    We re-slice it here for the raw 32-byte tuple the SAL verifier needs (it
    works on Ed25519 points, not on the verifier's decoded Weierstrass
    coordinates).

    Returns (ok, detail, per_input) where per_input is a list of
    {'ok', 'key_image', 'detail'}, one entry per input.
    """
    sig_hash = signable_tx_hash(tx)
    per_input = []
    statuses = []
    for i in range(n_inputs):
        base = i * _PER_INPUT
        O_tilde = fcmp_bytes[base : base + 32]
        I_tilde = fcmp_bytes[base + 32 : base + 64]
        R = fcmp_bytes[base + 64 : base + 96]
        sal_bytes = fcmp_bytes[base + 96 : base + _PER_INPUT]
        C_tilde = tx.pseudoOuts[i]
        key_image = tx.vin[i].k_image
        try:
            proof = _sal.SAL.from_bytes(sal_bytes)
            ok = _sal.verify(sig_hash, O_tilde, I_tilde, R, C_tilde, Point(key_image), proof)
            status = "ok" if ok else "fail"
            detail = "accepted" if ok else "SAL equations unsatisfied"
        except Exception as e:
            status, detail = _classify(e)
        statuses.append(status)
        per_input.append({"ok": status == "ok", "status": status,
                          "key_image": key_image.hex(), "detail": detail})
    overall = _worst(statuses)
    return overall, ("accepted" if overall == "ok" else "one or more inputs failed"), per_input


def check_bp(tx_json: dict) -> tuple:
    """Re-verify the Bulletproof+ range proof from the decoded transaction JSON."""
    try:
        ok = bool(check_rangeproofs.check_sig_bp_plus(tx_json))
        return ("ok" if ok else "fail"), ("accepted" if ok else "BP+ verification equation failed")
    except Exception as e:
        return _classify(e)


def check_balance(tx_json: dict) -> tuple:
    """Σ pseudoOuts − Σ outPk − fee·H == 0.

    check_rangeproofs.check_commitments cannot be reused here: it reads
    rct_signatures.pseudoOuts, but rct type 7 carries the pseudo-outs in
    rctsig_prunable.pseudoOuts, so it would pass vacuously on every FCMP++ tx.
    """
    try:
        rct = tx_json["rct_signatures"]
        prunable = tx_json.get("rctsig_prunable", {})
        pseudo_outs = prunable.get("pseudoOuts") or rct.get("pseudoOuts") or []
        if not pseudo_outs:
            return "fail", "no pseudoOuts found"
        Cin = df25519.Z
        for p in pseudo_outs:
            Cin = Cin + Point(p)
        Cout = df25519.Z
        for p in rct["outPk"]:
            Cout = Cout + Point(p)
        fee = Scalar(int(rct["txnFee"])) * df25519.H
        ok = (Cin - Cout - fee) == df25519.Z
        return ("ok" if ok else "fail"), ("balanced" if ok else "Σ pseudoOuts ≠ Σ outPk + fee·H")
    except Exception as e:
        return _classify(e)


# --------------------------------------------------------------------------- #
#  one transaction
# --------------------------------------------------------------------------- #


def verify_tx(tx_json: dict, blob_hex, tree_root_bytes: bytes, params,
              checks=ALL_CHECKS, txid=None) -> dict:
    """Verify one FCMP++ transaction.

    tx_json         decoded transaction JSON (RPC as_json / decode_as_json=true)
    blob_hex        the raw transaction blob as hex (RPC as_hex), may be None,
                    in which case the SAL check is skipped
    tree_root_bytes curve-tree root the tx's reference block commits to
    params          FcmpParams from input_params.txt
    checks          subset of ALL_CHECKS to run

    Returns a result dict:
        {'txid', 'ok', 'n_inputs', 'n_tree_layers', 'reference_block',
         'checks': {name: {'status': 'ok'|'fail'|'skip', 'detail': str, ...}}}
    A check is 'ok', 'fail' (the transaction is invalid), 'error' (this checker
    malfunctioned, which says nothing about the transaction) or 'skip'. ok is
    True only when every executed check is 'ok'.
    """
    result = {
        "txid": txid,
        "ok": False,
        "n_inputs": None,
        "n_tree_layers": None,
        "reference_block": None,
        "checks": {},
    }

    def record(name, status, detail, **extra):
        result["checks"][name] = dict(status=status, detail=detail, **extra)

    # -- parse ------------------------------------------------------------
    try:
        parsed = parse_fcmp_tx(tx_json)
    except Exception as e:
        record("parse", *_classify(e))
        return result
    if parsed is None:
        record("parse", "skip", "not an FCMP++ (rct type 7) transaction")
        return result

    n_inputs = parsed["n_inputs"]
    result["n_inputs"] = n_inputs
    result["n_tree_layers"] = parsed["n_tree_layers"]
    result["reference_block"] = parsed["reference_block"]

    # -- membership -------------------------------------------------------
    if "membership" in checks:
        status, detail, elapsed = check_membership(parsed, tree_root_bytes, params)
        record("membership", status, detail, seconds=elapsed)

    # -- SAL --------------------------------------------------------------
    if "sal" in checks:
        if blob_hex is None:
            record("sal", "skip", "no raw tx blob available (need RPC prune=false)")
        else:
            try:
                tx = _serialize.parse_tx(bytes.fromhex(blob_hex))
            except Exception as e:
                record("sal", "skip", f"tx blob not parseable: {type(e).__name__}: {e}")
                tx = None
            if tx is not None:
                fcmp_bytes = bytes.fromhex(tx_json["rctsig_prunable"]["fcmp_pp"])
                try:
                    status, detail, per_input = check_sal(tx, fcmp_bytes, n_inputs)
                    record("sal", status, detail, inputs=per_input)
                except Exception as e:
                    record("sal", *_classify(e))

    # -- BP+ --------------------------------------------------------------
    if "bp" in checks:
        record("bp", *check_bp(tx_json))

    # -- balance ----------------------------------------------------------
    if "balance" in checks:
        record("balance", *check_balance(tx_json))

    statuses = [c["status"] for c in result["checks"].values()]
    result["ok"] = bool(statuses) and all(s == "ok" for s in statuses)
    result["any_fail"] = any(s == "fail" for s in statuses)
    result["any_error"] = any(s == "error" for s in statuses)
    result["skipped"] = [n for n, c in result["checks"].items() if c["status"] == "skip"]
    return result


_MARK = {"ok": "OK  ", "fail": "FAIL", "skip": "skip", "error": "ERR "}


def format_result(result: dict, indent: str = "  ") -> str:
    """Human-readable multi-line summary of a verify_tx result."""
    lines = []
    head = result["txid"][:16] + "…" if result.get("txid") else "(tx)"
    lines.append(
        f"{indent}{head}  inputs={result['n_inputs']} layers={result['n_tree_layers']} "
        f"ref_block={result['reference_block']}"
    )
    for name in ("parse", "membership", "sal", "bp", "balance"):
        c = result["checks"].get(name)
        if c is None:
            continue
        extra = ""
        if name == "membership" and "seconds" in c:
            extra = f"  ({c['seconds']:.2f}s)"
        lines.append(f"{indent}  {_MARK[c['status']]}  {name:<11}{c['detail']}{extra}")
        if name == "sal":
            for i, inp in enumerate(c.get("inputs", [])):
                mark = _MARK["ok" if inp["ok"] else "fail"]
                lines.append(
                    f"{indent}         {mark}  input[{i}] L={inp['key_image'][:16]}…"
                    + ("" if inp["ok"] else f"  {inp['detail']}")
                )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  stats + logging
# --------------------------------------------------------------------------- #


_ZERO = {"ok": 0, "fail": 0, "error": 0, "skip": 0}


class Stats:
    """Running totals, per check as well as per transaction."""

    CHECKS = ALL_CHECKS

    def __init__(self):
        self.blocks = 0
        self.txs_total = 0
        self.txs_fcmp = 0
        self.txs_pass = 0
        self.txs_fail = 0
        self.inputs = 0
        self.seconds = 0.0
        self.per_check = {c: dict(_ZERO) for c in self.CHECKS}
        self.failures = []  # (height, txid, check, detail)
        self.errors = []    # same shape, but the checker broke rather than the tx

    def add(self, height, result):
        self.txs_fcmp += 1
        self.inputs += result["n_inputs"] or 0
        for name, c in result["checks"].items():
            slot = self.per_check.setdefault(name, dict(_ZERO))
            slot[c["status"]] = slot.get(c["status"], 0) + 1
            if c["status"] == "fail":
                self.failures.append((height, result["txid"], name, c["detail"]))
            elif c["status"] == "error":
                self.errors.append((height, result["txid"], name, c["detail"]))
        if result.get("any_fail") or result.get("any_error"):
            self.txs_fail += 1
        else:
            self.txs_pass += 1

    def block_line(self, height):
        checks = "  ".join(
            f"{n}:{v['ok']}ok" + (f"/{v['fail']}FAIL" if v["fail"] else "")
            + (f"/{v['error']}ERR" if v["error"] else "")
            + (f"/{v['skip']}skip" if v["skip"] else "")
            for n, v in self.per_check.items()
            if any(v.values())
        )
        return (
            f"height={height}  blocks={self.blocks}  fcmp_txs={self.txs_fcmp} "
            f"(pass {self.txs_pass} / fail {self.txs_fail})  inputs={self.inputs}  "
            f"{self.seconds:.1f}s\n    {checks}"
        )


def _setup_logging(log_path):
    logger = logging.getLogger("fcmp_scan")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    h = logging.FileHandler(log_path)
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)
    return logger


def _emit(logger, event, **fields):
    logger.info(json.dumps({"ts": time.time(), "event": event, **fields}))


# --------------------------------------------------------------------------- #
#  the block loop
# --------------------------------------------------------------------------- #


def tree_root_for(rpc, reference_block, cache):
    """Curve-tree root a transaction's reference_block (a lock index) commits to."""
    if reference_block in cache:
        return cache[reference_block]
    height = reference_block - LOCK_OFFSET
    bj = json.loads(rpc.get_block(height).get("json", "{}"))
    root_hex = bj.get("fcmp_pp_tree_root", "")
    if not root_hex:
        raise ValueError(f"block {height} (lock index {reference_block}) has no fcmp_pp_tree_root")
    cache[reference_block] = bytes.fromhex(root_hex)
    return cache[reference_block]


def scan_block(height, rpc, params, cache, checks, logger, stats, verbose=True):
    """Verify every FCMP++ transaction in one block. Returns the list of results."""
    block = rpc.get_block(height)

    # A block stores the tree root for lock index height + LOCK_OFFSET. Cache it
    # so a later tx referencing it needs no extra RPC round trip.
    try:
        bj = json.loads(block.get("json", "{}"))
        root_hex = bj.get("fcmp_pp_tree_root", "")
        if root_hex:
            cache[height + LOCK_OFFSET] = bytes.fromhex(root_hex)
    except Exception as e:
        _emit(logger, "tree_root_parse_error", height=height, error=str(e))

    tx_hashes = block.get("tx_hashes", []) or []
    stats.txs_total += len(tx_hashes)
    if not tx_hashes:
        return []

    resp = rpc.get_transactions(tx_hashes)
    entries = resp.get("txs", []) or []
    results = []

    for entry in entries:
        txid = entry.get("tx_hash", "")
        raw = entry.get("as_json")
        if not raw:
            continue
        try:
            tx_json = json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            _emit(logger, "tx_json_parse_failed", height=height, txid=txid, error=str(e))
            continue

        if tx_json.get("rct_signatures", {}).get("type") != RCT_TYPE_FCMP:
            continue  # not an FCMP++ tx

        blob_hex = entry.get("as_hex") or None
        t0 = time.perf_counter()
        try:
            root = tree_root_for(rpc, int(tx_json["rctsig_prunable"]["reference_block"]), cache)
        except Exception as e:
            _emit(logger, "tree_root_unavailable", height=height, txid=txid, error=str(e))
            if verbose:
                print(f"  {txid[:16]}…  tree root unavailable: {e}")
            continue

        result = verify_tx(tx_json, blob_hex, root, params, checks=checks, txid=txid)
        stats.seconds += time.perf_counter() - t0
        stats.add(height, result)
        results.append(result)

        # Record why, not just that: a bare status leaves a later reader unable to
        # tell a bad transaction from a broken checker without re-running the scan.
        _emit(logger, "tx_verified", height=height, txid=txid, ok=result["ok"],
              checks={n: c["status"] for n, c in result["checks"].items()},
              details={n: c["detail"].splitlines()[0] if c["detail"] else ""
                       for n, c in result["checks"].items() if c["status"] != "ok"})
        if verbose:
            print(format_result(result))

    return results


def run(args):
    params = load_params(args.params or PARAMS_FILE)

    if args.replay:
        rpc = ReplayRPC(args.replay)
        # A dump is finite, so there is nothing to poll for: stop at its end
        # rather than waiting for blocks that will never arrive.
        args.once = True
        print(f"[mode] REPLAY from {args.replay} (offline)")
    elif args.record:
        rpc = RecordingRPC(args.node, timeout=args.timeout)
        print(f"[mode] LIVE {args.node}, recording -> {args.record}")
    else:
        rpc = NodeRPC(args.node, timeout=args.timeout)
        print(f"[mode] LIVE {args.node}")

    checks = tuple(c.strip() for c in args.checks.split(",") if c.strip())
    unknown = set(checks) - set(ALL_CHECKS)
    if unknown:
        raise SystemExit(f"unknown check(s): {', '.join(sorted(unknown))}; "
                         f"choose from {', '.join(ALL_CHECKS)}")
    print(f"[checks] {', '.join(checks)}")

    log_path = paths.log_path("scan.log")
    stats_path = paths.log_path("scan_stats.log")
    logger = _setup_logging(log_path)
    print(f"[logs] {log_path}  {stats_path}")

    stats = Stats()
    cache = {}
    height = args.start_height
    end = args.end_height
    retries = 0

    try:
        while True:
            if end is not None and height > end:
                break
            try:
                tip = rpc.get_block_count()
            except Exception:
                tip = None
            if tip is not None and height >= tip:
                if args.once or end is not None:
                    print(f"[done] reached chain tip at height {tip}")
                    break
                time.sleep(args.poll_interval)
                continue

            try:
                results = scan_block(height, rpc, params, cache, checks, logger, stats,
                                     verbose=not args.quiet)
                retries = 0
            except (urllib.error.URLError, ConnectionError, OSError) as e:
                retries += 1
                if retries > args.max_retries:
                    print(f"[abort] node unreachable at height {height} after "
                          f"{args.max_retries} retries: {e}", flush=True)
                    _emit(logger, "node_unreachable", height=height, error=str(e))
                    return 2
                print(f"[warn] node unreachable at height {height}: {e}; retry "
                      f"{retries}/{args.max_retries} in {args.poll_interval}s", flush=True)
                time.sleep(args.poll_interval)
                continue
            except KeyError as e:  # replay dump ran out
                print(f"[done] {e}")
                break

            stats.blocks += 1
            if results or not args.quiet:
                line = stats.block_line(height)
                if results:
                    print(f"[stats] {line}")
                with open(stats_path, "a") as f:
                    f.write(line + "\n")
            height += 1
    except KeyboardInterrupt:
        print("\n[interrupted]")
    finally:
        if args.record and isinstance(rpc, RecordingRPC):
            rpc.save(args.record)
            print(f"[record] wrote {len(rpc.calls)} responses -> {args.record}")

    print()
    print("=" * 72)
    print(f"scanned {stats.blocks} block(s), {stats.txs_total} tx, "
          f"{stats.txs_fcmp} FCMP++ tx ({stats.inputs} inputs) in {stats.seconds:.1f}s")
    for name, v in stats.per_check.items():
        if any(v.values()):
            print(f"  {name:<11} ok={v['ok']:<6} fail={v['fail']:<6} "
                  f"error={v['error']:<6} skip={v['skip']}")
    if stats.failures:
        print(f"\n{len(stats.failures)} FAILURE(S) -- transactions that did not verify:")
        for h, txid, check, detail in stats.failures[:20]:
            print(f"  height {h}  {txid[:16]}…  {check}: {detail}")
    if stats.errors:
        # Not evidence about the chain. Says this checker has a bug.
        print(f"\n{len(stats.errors)} CHECKER ERROR(S) -- this tool malfunctioned, "
              "these say nothing about the transactions:")
        for h, txid, check, detail in stats.errors[:20]:
            print(f"  height {h}  {txid[:16]}…  {check}: {detail.splitlines()[0]}")
    if stats.failures or stats.errors:
        return 1
    print("\nno failures")
    return 0


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #


def build_parser(p=None):
    p = p or argparse.ArgumentParser(description="FCMP++ blockchain scanner")
    p.add_argument("--node", default=DEFAULT_NODE, help=f"daemon URL (default: {DEFAULT_NODE})")
    p.add_argument("--start-height", type=int, default=0, help="height to begin at")
    p.add_argument("--end-height", type=int, default=None, help="last height to scan (inclusive)")
    p.add_argument("--checks", default=",".join(ALL_CHECKS),
                   help="comma-separated subset of: " + ", ".join(ALL_CHECKS))
    p.add_argument("--params", default=None, help="path to input_params.txt")
    p.add_argument("--record", default=None, metavar="FILE", help="save RPC responses to FILE")
    p.add_argument("--replay", default=None, metavar="FILE", help="scan offline from FILE")
    p.add_argument("--poll-interval", type=float, default=5.0,
                   help="seconds to wait at the chain tip (default: 5)")
    p.add_argument("--once", action="store_true", help="stop at the tip instead of polling")
    p.add_argument("--max-retries", type=int, default=5,
                   help="give up after this many consecutive RPC failures (default: 5)")
    p.add_argument("--timeout", type=float, default=30.0, help="RPC timeout in seconds")
    p.add_argument("--quiet", action="store_true", help="only print blocks containing FCMP++ txs")
    return p


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
