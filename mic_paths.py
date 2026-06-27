"""mic_paths.py — sys.path bootstrap for the reorganized monero_inflation_checker.

The codebase uses flat, top-level imports (e.g. ``import df25519``,
``import check_rangeproofs``).  After the move into component directories
(``common/``, ``v1/``, ``mlsag/``, ``clsag/``, ``rangeproofs/``, ``fcmp/src``)
those bare module names no longer live next to each other, so importing this
module once from any entry point puts every component directory on ``sys.path``
and lets the existing flat imports keep resolving unchanged.

Entry points use the small "path bootstrap" header to locate this file (it walks
up the tree looking for ``mic_paths.py``) and then ``import mic_paths``.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))

# Component directories that hold importable modules, relative to the package
# root.  Order does not matter for correctness because the module base names are
# unique across directories.
_COMPONENT_DIRS = (
    "",  # root (orchestrators: MIC.py, verify_tx.py, ...)
    "common",  # shared crypto + helpers (df25519, settings, ...)
    "v1",  # check_v1
    "mlsag",  # check_mlsag
    "clsag",  # check_clsag
    "rangeproofs",  # check_rangeproofs
    "scanner",  # scan_bc, verify_tx
    os.path.join("fcmp", "src"),  # FCMP++ verifier/prover engine
)

for _rel in _COMPONENT_DIRS:
    _abs = os.path.join(_ROOT, _rel) if _rel else _ROOT
    if os.path.isdir(_abs) and _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Root-anchored output locations (independent of the current working dir).
# ---------------------------------------------------------------------------
ROOT = _ROOT
LOGS_DIR = os.path.join(ROOT, "logs")  # logger_*.log
STATS_DIR = os.path.join(ROOT, "stats")  # block_stats*.csv, height*.txt, last_block_scanned.txt


def log_path(name):
    """Absolute path for a log file under logs/ (created on demand)."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    return os.path.join(LOGS_DIR, name)


def stats_path(name):
    """Absolute path for a stats/state file under stats/ (created on demand)."""
    os.makedirs(STATS_DIR, exist_ok=True)
    return os.path.join(STATS_DIR, name)
