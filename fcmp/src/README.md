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
`polynomial.py`, `multiexp.py`, `fcmp_input_verifier.py`, `input_params.txt`) 

## Transaction-builder modules
Builds, signs and relays real FCMP++ (rct type 7, Carrot v1) Monero transactions in pure
Python, reusing this repo's crypto (`df25519`, the engine above, `check_rangeproofs`) and the
fixed membership prover (`gbp.py` + `fcmp.py`).

- `epee.py` — minimal epee portable-storage codec (for `.bin` RPCs)
- `rpc.py` — daemon RPC client (JSON + epee `.bin` + `send_raw_transaction`)
- `serialize.py` — FCMP++ tx (de)serializer (byte-exact)
- `scan.py` — open an owned output (recover x, y, amount, mask, key image)
- `treepath.py` — fetch + decode the curve-tree path (`get_path_by_unified_id.bin`)
- `treebuild.py` — map the path into the prover's `BranchesWithBlinds`
- `blinds.py` — re-randomization + output/branch divisor blinds
- `sal.py` — Spend-Authorization & Linkability proof
- `build_tx.py` — end-to-end: open input → outputs → membership proof → SAL → BP+ → serialize → relay

## Requirements
- The Bulletproof+ generator files (`Gi_plus_df.npy`, `Hi_plus_df.npy`, … in `common/`) and
  `input_params.txt` (consensus generators) must be present — same files the verifier uses.
