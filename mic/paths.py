"""Root-anchored output locations, independent of the working directory.

Only where the tool *writes*: logs and scan statistics. Nothing here touches
sys.path. Imports resolve through the package.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(ROOT, "logs")    # logger_*.log
STATS_DIR = os.path.join(ROOT, "stats")  # block_stats*.csv, height*.txt, ...


def log_path(name):
    """Absolute path for a log file under logs/ (created on demand)."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    return os.path.join(LOGS_DIR, name)


def stats_path(name):
    """Absolute path for a stats/state file under stats/ (created on demand)."""
    os.makedirs(STATS_DIR, exist_ok=True)
    return os.path.join(STATS_DIR, name)


__all__ = ["ROOT", "LOGS_DIR", "STATS_DIR", "log_path", "stats_path"]
