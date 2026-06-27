#!/usr/bin/env python3
"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

FCMP++ blockchain scanner.

Pulls blocks from a local Monero node via JSON-RPC, verifies every FCMP++
transaction in each block, and advances to the next block.

Two log files are written to the same directory as this script:
  scanner.log       JSON-lines — one event per line; machine-parseable
  scanner_stats.log human-readable stats block appended after each block

Usage:
    python scanner.py [--node http://127.0.0.1:18081] [--start-height N]
                      [--params /path/to/input_params.txt] [--poll-interval 5]
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

# ── MIC source path ────────────────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_MIC_SRC = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", "src"))
sys.path.insert(0, _MIC_SRC)

from field import HeliosField, SeleneField
from curve import oc_from_bytes, selene_from_bytes, helios_from_bytes, SELENE_B, HELIOS_B
from gbp import Generators
from fcmp import Fcmp, FcmpParams
from circuit import CurveSpec, GeneratorTable, OC_PARAMS, C1_PARAMS, C2_PARAMS
from divisors import WEI25519_A, WEI25519_B

# ── Blob layout (fcmp_pp_proof_from_parts_v1 in fcmp_pp_types.cpp) ────────────
#   per input:  O_tilde(32) | I_tilde(32) | R(32) | SAL_proof(12×32 = 384)
#   then:       membership proof body
#   last 64:    root_blind_PoK
_INPUT_TUPLE = 3 * 32  # 96 bytes: O_tilde + I_tilde + R
_SAL_SIZE = 12 * 32  # 384 bytes
_PER_INPUT = _INPUT_TUPLE + _SAL_SIZE  # 480 bytes per input
_POK_SIZE = 64  # root_blind Schnorr PoK

RCT_TYPE_FCMP = 7  # rct::RCTTypeFcmpPlusPlus

# reference_block in the TX is a LOCK INDEX, not a block height.
# Block header at height H stores the tree root at lock_index H + 8:
#   get_default_last_locked_block_index(H-1) = (H-1) + (SPENDABLE_AGE-1) = H+8
# So to look up the tree root for lock_index K we need block height K-8.
_SPENDABLE_AGE = 10
_TREE_ROOT_LOCK_OFFSET = _SPENDABLE_AGE - 2  # = 8

_W = 74  # stats log line width


# ── Session statistics tracker ─────────────────────────────────────────────────


class StatsTracker:
    """Accumulates verification statistics across the scanner session."""

    def __init__(self, session_start: float):
        self.session_start = session_start

        # Session-level counters
        self.blocks_scanned = 0
        self.blocks_with_fcmp = 0
        self.total_txs_seen = 0  # non-coinbase TXs across all blocks
        self.total_fcmp = 0
        self.total_pass = 0
        self.total_fail = 0
        self.total_verify_s = 0.0

        # Per-TX timing breakdowns
        # key = n_inputs, value = list of (ms, tx_hash, height, n_layers) tuples
        self.by_inputs: dict[int, list] = defaultdict(list)
        # key = n_tree_layers, value = list of ms timings
        self.by_layers: dict[int, list] = defaultdict(list)

        # Extremes
        self.fastest: Optional[dict] = None  # {ms, tx_hash, height, n_inputs, n_layers}
        self.slowest: Optional[dict] = None

    def record_tx(
        self,
        *,
        height: int,
        tx_hash: str,
        n_inputs: int,
        n_layers: int,
        elapsed_ms: float,
        passed: bool,
    ):
        self.total_fcmp += 1
        if passed:
            self.total_pass += 1
            self.total_verify_s += elapsed_ms / 1000
            rec = dict(
                ms=elapsed_ms, tx_hash=tx_hash, height=height, n_inputs=n_inputs, n_layers=n_layers
            )
            self.by_inputs[n_inputs].append(rec)
            self.by_layers[n_layers].append(elapsed_ms)
            if self.fastest is None or elapsed_ms < self.fastest["ms"]:
                self.fastest = rec
            if self.slowest is None or elapsed_ms > self.slowest["ms"]:
                self.slowest = rec
        else:
            self.total_fail += 1

    def record_block(self, *, n_txs: int, had_fcmp: bool):
        self.blocks_scanned += 1
        self.total_txs_seen += n_txs
        if had_fcmp:
            self.blocks_with_fcmp += 1

    def ms_per_input_avg(self) -> Optional[float]:
        """Average ms per-input across all verified TXs (total_verify_s / total_inputs)."""
        total_inputs = sum(
            len(v) * k for k, v in self.by_inputs.items() if isinstance(k, int) and len(v) > 0
        )
        if total_inputs == 0:
            return None
        return self.total_verify_s * 1000 / total_inputs

    def uptime(self) -> str:
        s = int(time.monotonic() - self.session_start)
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        return f"{h}:{m:02d}:{sec:02d}"


# ── Stats log writer ───────────────────────────────────────────────────────────


def _bar(char: str = "═") -> str:
    return char * _W


def _sec(title: str, char: str = "─") -> str:
    return f" {title} ".center(_W, char)


def _kv(key: str, value: str, width: int = 18) -> str:
    return f" {key:<{width}} : {value}"


def write_stats_block(
    stats_path: str,
    tracker: StatsTracker,
    height: int,
    block_wall_ms: float,
    block_tx_records: list,
    block_total_txs: int,
):
    """Append one stats block to scanner_stats.log."""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    block_pass = sum(1 for r in block_tx_records if r["passed"])
    block_fail = sum(1 for r in block_tx_records if not r["passed"])
    block_fcmp = len(block_tx_records)
    block_other = block_total_txs - block_fcmp
    block_ms = sum(r["elapsed_ms"] for r in block_tx_records if r["passed"])

    lines = []
    lines.append(_bar("═"))
    lines.append(f" Block {height}  |  {ts}  |  wall {block_wall_ms:.0f} ms")
    lines.append(_bar("─"))

    # TX breakdown
    fcmp_summary = (
        f"{block_fcmp} FCMP++ ({block_pass} PASS"
        + (f", {block_fail} FAIL" if block_fail else "")
        + ")"
    )
    non_fcmp = f"{block_other} non-FCMP skipped" if block_other else ""
    total_desc = "  ·  ".join(filter(None, [fcmp_summary, non_fcmp]))
    lines.append(_kv("TXs in block", f"{block_total_txs} total — {total_desc}"))

    # Per-TX timings
    if block_tx_records:
        lines.append(_kv("Verify times", ""))
        for r in block_tx_records:
            tag = f"n_inputs={r['n_inputs']}  layers={r['n_layers']}"
            if r["passed"]:
                val = f"{r['elapsed_ms']:.0f} ms   [{r['tx_hash'][:16]}…]"
            else:
                val = f"FAIL  [{r['tx_hash'][:16]}…]  {r.get('error','')[:40]}"
            lines.append(f"   {tag:<32} {val}")
        if block_pass > 0:
            lines.append(_kv("Block verify total", f"{block_ms:.0f} ms"))
    else:
        lines.append(_kv("Verify times", "(no FCMP++ TXs)"))

    # Session totals
    lines.append(_bar("─"))
    lines.append(f" Session totals  (uptime {tracker.uptime()})")
    lines.append(_bar("─"))
    lines.append(
        _kv("Blocks scanned", f"{tracker.blocks_scanned}  ({tracker.blocks_with_fcmp} with FCMP++)")
    )
    lines.append(
        _kv(
            "FCMP++ TXs",
            f"{tracker.total_pass} pass  ·  {tracker.total_fail} fail"
            + ("  ← ALERT" if tracker.total_fail > 0 else ""),
        )
    )

    # by n_inputs table
    if tracker.by_inputs:
        lines.append(_kv("By n_inputs", ""))
        for n in sorted(tracker.by_inputs):
            recs = tracker.by_inputs[n]
            times = [r["ms"] for r in recs]
            avg = sum(times) / len(times)
            mn = min(times)
            mx = max(times)
            lines.append(
                f"   {n} input{'s' if n != 1 else '':<5}"
                f"  {len(recs):>4} TXs"
                f"  avg {avg:>6.0f} ms"
                f"  min {mn:>6.0f} ms"
                f"  max {mx:>6.0f} ms"
            )

    # by n_tree_layers table
    if tracker.by_layers:
        lines.append(_kv("By n_layers", ""))
        for n in sorted(tracker.by_layers):
            times = tracker.by_layers[n]
            avg = sum(times) / len(times)
            lines.append(f"   {n} layers" f"  {len(times):>4} TXs" f"  avg {avg:>6.0f} ms")

    # ms-per-input
    mpi = tracker.ms_per_input_avg()
    if mpi is not None:
        lines.append(_kv("ms / input (avg)", f"{mpi:.0f} ms"))

    # Extremes
    if tracker.fastest:
        f = tracker.fastest
        lines.append(
            _kv(
                "Fastest TX",
                f"{f['tx_hash'][:16]}…  block {f['height']}"
                f"  {f['n_inputs']}in/{f['n_layers']}lay"
                f"  {f['ms']:.0f} ms",
            )
        )
    if tracker.slowest:
        s = tracker.slowest
        lines.append(
            _kv(
                "Slowest TX",
                f"{s['tx_hash'][:16]}…  block {s['height']}"
                f"  {s['n_inputs']}in/{s['n_layers']}lay"
                f"  {s['ms']:.0f} ms",
            )
        )

    lines.append(_kv("Total verify", f"{tracker.total_verify_s:.1f} s accumulated"))
    lines.append(_bar("═"))
    lines.append("")  # blank line between blocks

    with open(stats_path, "a") as f:
        f.write("\n".join(lines) + "\n")


# ── Logging (scanner.log) ─────────────────────────────────────────────────────


def _setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("scanner")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(fh)

    return logger


def _emit(logger: logging.Logger, level: str, event: str, **fields):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        **fields,
    }
    line = json.dumps(rec, default=str)
    if level in ("ERROR", "CRITICAL"):
        logger.error(line)
    elif level == "WARNING":
        logger.warning(line)
    elif level == "DEBUG":
        logger.debug(line)
    else:
        logger.info(line)


# ── Monero JSON-RPC client ─────────────────────────────────────────────────────


class NodeRPC:
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

    def get_transactions(self, tx_hashes: list[str]) -> dict:
        return self._post(
            "get_transactions",
            {
                "txs_hashes": tx_hashes,
                "decode_as_json": True,
            },
        )


# ── FcmpParams loading ─────────────────────────────────────────────────────────


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


def load_params(params_path: str) -> FcmpParams:
    kv = _parse_kv(params_path)

    from curve import WPoint

    id_c1 = WPoint.identity(SeleneField, SELENE_B)
    id_c2 = WPoint.identity(HeliosField, HELIOS_B)

    def _sel(key):
        return selene_from_bytes(bytes.fromhex(kv[key]))

    def _hel(key):
        return helios_from_bytes(bytes.fromhex(kv[key]))

    c1_gens = Generators(
        _sel("curve_1_generators.g"),
        _sel("curve_1_generators.h"),
        [_sel(f"curve_1_generators.g_bold[{i}]") for i in range(512)],
        [_sel(f"curve_1_generators.h_bold[{i}]") for i in range(512)],
        id_c1,
    )
    c2_gens = Generators(
        _hel("curve_2_generators.g"),
        _hel("curve_2_generators.h"),
        [_hel(f"curve_2_generators.g_bold[{i}]") for i in range(256)],
        [_hel(f"curve_2_generators.h_bold[{i}]") for i in range(256)],
        id_c2,
    )

    OC_SPEC = CurveSpec(HeliosField(WEI25519_A), HeliosField(WEI25519_B))
    C1_SPEC = CurveSpec(SeleneField(SeleneField.P - 3), SELENE_B)
    C2_SPEC = CurveSpec(HeliosField(HeliosField.P - 3), HELIOS_B)

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


def _find_params(explicit: Optional[str]) -> str:
    if explicit and os.path.exists(explicit):
        return explicit
    for c in [
        os.path.join(_MIC_SRC, "input_params.txt"),
        os.path.normpath(os.path.join(_SCRIPT_DIR, "../../../monero_oxide/input_params.txt")),
    ]:
        if os.path.exists(c):
            return c
    raise FileNotFoundError(
        "Cannot find input_params.txt — pass --params <path> or place it alongside "
        "monero_inflation_checker/fcmp/src/"
    )


# ── Proof parsing ──────────────────────────────────────────────────────────────


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


# ── Single-TX verification ─────────────────────────────────────────────────────


def verify_tx(parsed: dict, tree_root_bytes: bytes, params: FcmpParams) -> float:
    """Run Fcmp.verify() for one FCMP++ TX.  Returns elapsed seconds.

    Raises on verification failure or any exception inside Fcmp.verify().
    """
    layers = parsed["n_tree_layers"]  # NOT ×2 — Fcmp.verify() takes n_tree_layers directly
    is_c1 = (layers % 2) == 1  # odd → root on C1/Selene, even → C2/Helios

    counter = [0]

    def rng_fn():
        counter[0] += 1
        return SeleneField(counter[0])

    v1 = Generators.new_batch_verifier(512, HeliosField)
    v2 = Generators.new_batch_verifier(256, SeleneField)

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


# ── Single TX-file verification ────────────────────────────────────────────────


def fetch_tree_root(rpc: NodeRPC, ref_block: int) -> bytes:
    """Return the FCMP++ tree root for a given reference_block (a lock index).

    reference_block is a LOCK INDEX, not a block height: the tree root for
    lock_index K is stored in the block at height K - _TREE_ROOT_LOCK_OFFSET.
    """
    ref_height = ref_block - _TREE_ROOT_LOCK_OFFSET
    bj = json.loads(rpc.get_block(ref_height).get("json", "{}"))
    tree_root_hex = bj.get("fcmp_pp_tree_root", "")
    if not tree_root_hex:
        raise ValueError(f"block {ref_height} (lock_idx {ref_block}) missing fcmp_pp_tree_root")
    return bytes.fromhex(tree_root_hex)


def verify_tx_file(path: str, rpc: NodeRPC, params: FcmpParams) -> bool:
    """Verify a single decoded TX JSON file (RPC as_json format).

    Returns True if the FCMP++ proof verifies.  Prints a human-readable summary.
    """
    with open(path) as f:
        tx_json = json.load(f)

    parsed = parse_fcmp_tx(tx_json)
    if parsed is None:
        print(f"[{path}] not an FCMP++ TX (rct type != {RCT_TYPE_FCMP}) — nothing to verify")
        return False

    ref_block = parsed["reference_block"]
    print(
        f"[parse] inputs={parsed['n_inputs']} layers={parsed['n_tree_layers']} "
        f"reference_block(lock_index)={ref_block}"
    )

    tree_root = fetch_tree_root(rpc, ref_block)
    print(f"[node]  tree root @ block {ref_block - _TREE_ROOT_LOCK_OFFSET}: {tree_root.hex()}")

    try:
        elapsed = verify_tx(parsed, tree_root, params)
    except Exception as e:
        print(f"\n[result] INVALID — {e}")
        return False

    print(f"\n[result] VALID — Fcmp.verify() passed in {elapsed * 1000:.0f} ms")
    return True


# ── Block processing ───────────────────────────────────────────────────────────


def process_block(
    height: int, rpc: NodeRPC, params: FcmpParams, root_cache: dict, logger: logging.Logger
) -> tuple[dict, list]:
    """Fetch and verify all FCMP++ TXs in block at `height`.

    Returns (stats, tx_records) where:
      stats      = {fcmp_count, pass_count, fail_count, skip_count, elapsed_s, total_txs}
      tx_records = [{tx_hash, n_inputs, n_layers, elapsed_ms, passed, error?}]
    """
    stats = {
        "fcmp_count": 0,
        "pass_count": 0,
        "fail_count": 0,
        "skip_count": 0,
        "elapsed_s": 0.0,
        "total_txs": 0,
    }
    tx_records: list = []

    block_result = rpc.get_block(height)

    # Cache this block's FCMP++ tree root from block JSON field
    try:
        bj = json.loads(block_result.get("json", "{}"))
        tree_root_hex = bj.get("fcmp_pp_tree_root", "")
        if tree_root_hex:
            # Block H stores tree root at lock_index H + _TREE_ROOT_LOCK_OFFSET (= H+8).
            # Cache by lock_index so lookups by reference_block (a lock_index) hit directly.
            root_cache[height + _TREE_ROOT_LOCK_OFFSET] = bytes.fromhex(tree_root_hex)
    except Exception as e:
        _emit(logger, "WARNING", "tree_root_parse_error", height=height, error=str(e))

    tx_hashes = block_result.get("tx_hashes", [])
    stats["total_txs"] = len(tx_hashes)
    if not tx_hashes:
        return stats, tx_records

    try:
        tx_response = rpc.get_transactions(tx_hashes)
    except Exception as e:
        _emit(logger, "ERROR", "get_transactions_failed", height=height, error=str(e))
        return stats, tx_records

    txs_as_json = tx_response.get("txs_as_json", [])
    tx_meta = tx_response.get("txs", [])
    tx_hashes_ret = [t.get("tx_hash", "") for t in tx_meta]
    if len(tx_hashes_ret) != len(txs_as_json):
        tx_hashes_ret = tx_hashes[: len(txs_as_json)]

    for idx, tx_raw in enumerate(txs_as_json):
        tx_hash = tx_hashes_ret[idx] if idx < len(tx_hashes_ret) else f"unknown[{idx}]"

        try:
            tx_json = json.loads(tx_raw) if isinstance(tx_raw, str) else tx_raw
        except Exception as e:
            _emit(
                logger,
                "ERROR",
                "tx_json_parse_failed",
                height=height,
                tx_hash=tx_hash,
                error=str(e),
            )
            stats["fail_count"] += 1
            tx_records.append(
                {
                    "tx_hash": tx_hash,
                    "n_inputs": 0,
                    "n_layers": 0,
                    "elapsed_ms": 0.0,
                    "passed": False,
                    "error": str(e),
                }
            )
            continue

        try:
            parsed = parse_fcmp_tx(tx_json)
        except Exception as e:
            _emit(logger, "ERROR", "tx_parse_failed", height=height, tx_hash=tx_hash, error=str(e))
            stats["fail_count"] += 1
            tx_records.append(
                {
                    "tx_hash": tx_hash,
                    "n_inputs": 0,
                    "n_layers": 0,
                    "elapsed_ms": 0.0,
                    "passed": False,
                    "error": str(e),
                }
            )
            continue

        if parsed is None:
            stats["skip_count"] += 1
            continue

        stats["fcmp_count"] += 1
        ref_block = parsed["reference_block"]
        n_inputs = parsed["n_inputs"]
        n_layers = parsed["n_tree_layers"]

        # Fetch tree root at reference_block (from cache or node)
        tree_root_bytes = root_cache.get(ref_block)
        if tree_root_bytes is None:
            try:
                # reference_block is a LOCK INDEX, not a block height.
                # Block at height H stores tree root at lock_index H + _TREE_ROOT_LOCK_OFFSET.
                # So to get tree root at lock_index ref_block, fetch block at height ref_block - 8.
                ref_height = ref_block - _TREE_ROOT_LOCK_OFFSET
                ref_bj = json.loads(rpc.get_block(ref_height).get("json", "{}"))
                tree_root_hex = ref_bj.get("fcmp_pp_tree_root", "")
                if not tree_root_hex:
                    raise ValueError(
                        f"block {ref_height} (lock_idx {ref_block}) missing fcmp_pp_tree_root"
                    )
                tree_root_bytes = bytes.fromhex(tree_root_hex)
                root_cache[ref_block] = tree_root_bytes  # keyed by lock_index
            except Exception as e:
                _emit(
                    logger,
                    "ERROR",
                    "tree_root_fetch_failed",
                    height=height,
                    tx_hash=tx_hash,
                    ref_block=ref_block,
                    error=str(e),
                )
                stats["fail_count"] += 1
                tx_records.append(
                    {
                        "tx_hash": tx_hash,
                        "n_inputs": n_inputs,
                        "n_layers": n_layers,
                        "elapsed_ms": 0.0,
                        "passed": False,
                        "error": str(e),
                    }
                )
                continue

        try:
            elapsed = verify_tx(parsed, tree_root_bytes, params)
            ms = elapsed * 1000
            stats["pass_count"] += 1
            stats["elapsed_s"] += elapsed
            tx_records.append(
                {
                    "tx_hash": tx_hash,
                    "n_inputs": n_inputs,
                    "n_layers": n_layers,
                    "elapsed_ms": ms,
                    "passed": True,
                }
            )
            _emit(
                logger,
                "INFO",
                "TX_PASS",
                height=height,
                tx_hash=tx_hash,
                n_inputs=n_inputs,
                n_tree_layers=n_layers,
                proof_bytes=parsed["proof_bytes_len"],
                ref_block=ref_block,
                elapsed_ms=round(ms, 1),
            )
        except Exception as e:
            stats["fail_count"] += 1
            tx_records.append(
                {
                    "tx_hash": tx_hash,
                    "n_inputs": n_inputs,
                    "n_layers": n_layers,
                    "elapsed_ms": 0.0,
                    "passed": False,
                    "error": str(e),
                }
            )
            _emit(
                logger,
                "ERROR",
                "TX_FAIL",
                height=height,
                tx_hash=tx_hash,
                n_inputs=n_inputs,
                n_tree_layers=n_layers,
                ref_block=ref_block,
                error=str(e),
            )

    return stats, tx_records


# ── Main loop ──────────────────────────────────────────────────────────────────


def run(args):
    # Single-TX mode: verify one decoded TX JSON file and exit (no scan loop, no logs).
    if args.tx:
        params = load_params(_find_params(args.params))
        print(f"[setup] params loaded from {_find_params(args.params)}")
        rpc = NodeRPC(args.node, timeout=args.timeout)
        ok = verify_tx_file(args.tx, rpc, params)
        sys.exit(0 if ok else 1)

    log_path = os.path.join(_SCRIPT_DIR, "scanner.log")
    stats_path = os.path.join(_SCRIPT_DIR, "scanner_stats.log")
    logger = _setup_logging(log_path)

    session_start = time.monotonic()
    tracker = StatsTracker(session_start)

    _emit(
        logger,
        "INFO",
        "scanner_start",
        node=args.node,
        start_height=args.start_height,
        log=log_path,
        stats_log=stats_path,
    )

    params_path = _find_params(args.params)
    _emit(logger, "INFO", "loading_params", path=params_path)
    try:
        params = load_params(params_path)
    except Exception as e:
        _emit(logger, "CRITICAL", "params_load_failed", path=params_path, error=str(e))
        sys.exit(1)
    _emit(logger, "INFO", "params_loaded")

    rpc = NodeRPC(args.node, timeout=args.timeout)
    root_cache: dict[int, bytes] = {}
    current_height = args.start_height
    consecutive_err = 0

    while True:
        try:
            tip = rpc.get_block_count() - 1
            consecutive_err = 0
        except Exception as e:
            consecutive_err += 1
            wait = min(2**consecutive_err, 60)
            _emit(
                logger,
                "WARNING",
                "node_unreachable",
                error=str(e),
                retry_in_s=wait,
                consecutive_errors=consecutive_err,
            )
            time.sleep(wait)
            continue

        if current_height > tip:
            _emit(
                logger,
                "DEBUG",
                "waiting_for_block",
                current=current_height,
                tip=tip,
                poll_interval=args.poll_interval,
            )
            time.sleep(args.poll_interval)
            continue

        t_block = time.perf_counter()
        try:
            stats, tx_records = process_block(current_height, rpc, params, root_cache, logger)
        except Exception as e:
            _emit(logger, "ERROR", "block_process_exception", height=current_height, error=str(e))
            stats = {
                "fcmp_count": 0,
                "pass_count": 0,
                "fail_count": 1,
                "skip_count": 0,
                "elapsed_s": 0.0,
                "total_txs": 0,
            }
            tx_records = []

        block_wall_ms = (time.perf_counter() - t_block) * 1000

        # Update session tracker
        for rec in tx_records:
            if rec["n_inputs"] > 0:
                tracker.record_tx(
                    height=current_height,
                    tx_hash=rec["tx_hash"],
                    n_inputs=rec["n_inputs"],
                    n_layers=rec["n_layers"],
                    elapsed_ms=rec["elapsed_ms"],
                    passed=rec["passed"],
                )
        tracker.record_block(
            n_txs=stats["total_txs"],
            had_fcmp=stats["fcmp_count"] > 0,
        )

        # Write stats block
        write_stats_block(
            stats_path,
            tracker,
            current_height,
            block_wall_ms,
            tx_records,
            stats["total_txs"],
        )

        _emit(
            logger,
            "INFO",
            "block_done",
            height=current_height,
            total_txs=stats["total_txs"],
            fcmp_txs=stats["fcmp_count"],
            pass_=stats["pass_count"],
            fail=stats["fail_count"],
            skipped=stats["skip_count"],
            verify_ms=round(stats["elapsed_s"] * 1000, 1),
            block_wall_ms=round(block_wall_ms, 1),
        )

        if stats["fail_count"] > 0:
            _emit(
                logger,
                "ERROR",
                "INFLATION_ALERT",
                height=current_height,
                fail_count=stats["fail_count"],
                message="One or more FCMP++ proofs FAILED verification — "
                "possible inflation or malleability; manual investigation required.",
            )

        current_height += 1


# ── Entry point ────────────────────────────────────────────────────────────────


def _parse_args():
    p = argparse.ArgumentParser(
        description="FCMP++ blockchain scanner — verifies every FCMP++ TX in each block"
    )
    p.add_argument(
        "--node",
        default="http://127.0.0.1:18081",
        help="Monero daemon URL (default: http://127.0.0.1:18081)",
    )
    p.add_argument(
        "--start-height", type=int, default=0, help="Block height to begin scanning (default: 0)"
    )
    p.add_argument(
        "--tx",
        default=None,
        metavar="FILE",
        help="Verify a single decoded TX JSON file (RPC as_json format) instead of scanning",
    )
    p.add_argument(
        "--params", default=None, help="Path to input_params.txt (auto-discovered if omitted)"
    )
    p.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Seconds to wait when caught up to chain tip (default: 5)",
    )
    p.add_argument(
        "--timeout", type=float, default=30.0, help="RPC request timeout in seconds (default: 30)"
    )
    return p.parse_args()


if __name__ == "__main__":
    run(_parse_args())
