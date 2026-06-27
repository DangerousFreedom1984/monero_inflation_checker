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

import scan_bc
import settings_df25519
import time

init = time.time()
settings_df25519.node_choice(1)
initial_block = 0
count_blocks = 3400000
total_sum = scan_bc.get_coinbase_sum(initial_block, count_blocks)
print("Initial block: ", initial_block)
print("Final block (not included): ", initial_block + count_blocks)
print("Total sum: ", total_sum)
print("Total elapsed time: (s) ", time.time() - init)
