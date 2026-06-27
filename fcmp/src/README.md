# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments

This project uses [`monero-oxide`](https://github.com/monero-oxide/monero-oxide) (specifically the `monero-oxide` crate), which is licensed under the **MIT License**.

### License Notice
Copyright (c) 2022-2025 Luke Parker  
Copyright (c) 2025-2026 monero-oxide Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

# fcmp/src — FCMP++ (Carrot) engine + transaction builder

This directory holds both the **verifier/prover engine** (`fcmp.py`, `gbp.py`,
`curve.py`, `circuit.py`, `divisors.py`, `field.py`, `tape.py`, `transcript.py`,
`polynomial.py`, `multiexp.py`, `fcmp_input_verifier.py`, `input_params.txt`) and
the **pure-Python transaction builder** (formerly `fcmp/tx/`).

## Transaction-builder modules
Builds, signs and relays real FCMP++ (rct type 7, Carrot v1) Monero transactions in pure
Python, reusing this repo's crypto (`df25519`, the engine above, `check_rangeproofs`) and the
fixed membership prover (`gbp.py` + `fcmp.py`).

- `epee.py` — minimal epee portable-storage codec (for `.bin` RPCs)
- `rpc.py` — daemon RPC client (JSON + epee `.bin` + `send_raw_transaction`)
- `serialize.py` — FCMP++ tx (de)serializer (byte-exact)
- `carrot.py` — Carrot primitives: T/U/V generators, x25519, blake2b transcripts, scan + sender
- `keys.py` — load the wallet spend/view keys + base58 address decode
- `scan.py` — open an owned output (recover x, y, amount, mask, key image)
- `treepath.py` — fetch + decode the curve-tree path (`get_path_by_unified_id.bin`)
- `treebuild.py` — map the path into the prover's `BranchesWithBlinds`
- `blinds.py` — re-randomization + output/branch divisor blinds
- `sal.py` — Spend-Authorization & Linkability proof
- `build_tx.py` — end-to-end: open input → outputs → membership proof → SAL → BP+ → serialize → relay

## Requirements
- `pip install pynacl pycryptodome numpy requests gmpy2`
- The Bulletproof+ generator files (`Gi_plus_df.npy`, `Hi_plus_df.npy`, … in `common/`) and
  `input_params.txt` (consensus generators) must be present — same files the verifier uses.
- Wallet keys: set `FCMP_TX_KEYS` to the path of the CLI `spendkey`/`viewkey` dump and
  `FCMP_TX_ADDRESS_FILE` to the address file (both absolute paths).

## Usage
```bash
export FCMP_TX_KEYS=/abs/path/tn1.keys
export FCMP_TX_ADDRESS_FILE=/abs/path/tn1.address.txt
# verify-only (do_not_relay): build + on-node consensus check, no broadcast
python fcmp/src/build_tx.py <TXID_of_output_to_spend>
# actually relay (broadcast):
python fcmp/src/build_tx.py <TXID_of_output_to_spend> --relay
```
Edit `DEFAULT_NODE` in `rpc.py`, and `FEE`/`PAY` in `build_tx.py` as needed. `reference_block`
is `tip − ref_offset` (default 15); the builder retries on the transient near-tip tree race.

Validated: 5 self-spend transactions built this way were relayed and confirmed on-chain.

