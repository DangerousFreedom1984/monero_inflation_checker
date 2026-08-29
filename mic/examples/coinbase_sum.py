"""Sum every coinbase output up to a given height, against a local node.

    python mic/examples/coinbase_sum.py
"""

from mic.chain import scan_bc
from mic.common import settings_df25519
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
