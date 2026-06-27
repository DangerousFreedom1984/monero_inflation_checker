# Tutorial — scan & verify FCMP++ transactions in pure Python

This walks through verifying FCMP++ (Carrot) transactions with the **Monero Inflation
Checker** — either one transaction at a time or by continuously scanning the chain. All
proof verification is pure Python, using only the code in `monero_inflation_checker/`.

> **Building and relaying transactions** has moved to the separate **`mic_wallet`** project.
> This repository is the *verifier*: it checks that every FCMP++ proof is valid (no inflation),
> it does not create transactions.

---

## 0. Prerequisites

```bash
# from the repo root
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # numpy, PyNaCl, requests, pycryptodome
```

**Node** — verification reads chain data (blocks and the FCMP++ tree root) from a Monero
daemon over JSON-RPC. Point the scanner at any node that serves FCMP++ blocks with
`--node http://HOST:PORT` (default `http://127.0.0.1:18081`).

Each module bootstraps its own `sys.path`, so you can run the commands below from the repo
root; the scanner writes its log files next to `scanner.py` (in `fcmp/scanner/`).

---

## A. Verify a single transaction

A decoded on-chain FCMP++ tx (`fa4c01c1…`, 2 inputs, 6 layers) ships in `fcmp/tests/`:

```bash
python fcmp/scanner/scanner.py --tx fcmp/tests/fa4.json --node http://127.0.0.1:18081
# [parse]  inputs=2 layers=6 reference_block(lock_index)=...
# [node]   tree root @ block ...: <root hex>
# [result] VALID — Fcmp.verify() passed in ... ms
```

What it does:

| Step | Needs node? |
|------|-------------|
| parse the tx JSON, locate the FCMP++ proof (`rct` type 7) | no |
| fetch the tree root for the tx's `reference_block` | **yes** (`get_block` → `fcmp_pp_tree_root`) |
| run the consensus membership/balance verifier (`Fcmp.verify`) | no |

Only the tree-root lookup touches the node — the cryptographic verification is fully offline.
`reference_block` in the proof is a **lock index**, not a block height: the tree root for lock
index *K* lives in the block header at height *K − 8*; the scanner handles that offset for you.

The consensus parameters (`fcmp/src/input_params.txt`) are auto-discovered; override with
`--params /path/to/input_params.txt` if needed.

---

## B. Scan the chain continuously

Verify **every** FCMP++ transaction in every block, starting from a height and following the
chain tip:

```bash
python fcmp/scanner/scanner.py \
       --node http://127.0.0.1:18081 \
       --start-height 0
```

For each block the scanner fetches every transaction, verifies the FCMP++ proofs, and advances.
When it catches up to the tip it waits `--poll-interval` seconds (default 5) and retries, so you
can leave it running as a live monitor.

Useful flags:
- `--start-height N` — height to begin scanning (default 0).
- `--poll-interval S` — seconds to wait at the chain tip before polling again (default 5).
- `--timeout S` — per-RPC request timeout in seconds (default 30).

---

## C. Outputs

The scanner writes two files alongside `scanner.py` (`fcmp/scanner/`):

- `scanner.log` — **JSON-lines**, one event per line (block processed, tx verified, failures).
  Machine-parseable for alerting/auditing.
- `scanner_stats.log` — a human-readable stats block appended after each block (FCMP++ tx count,
  pass/fail/skip counts, timing).

A failed verification is the signal that matters: it means a transaction's FCMP++ proof did not
validate against the consensus rules.

---

## D. Inspecting a transaction's fields (optional)

To understand the structure of a tx and its proof (inputs, outputs, BP+ range proof, the
`fcmp_pp` proof layout), use the field explainer:

```bash
python fcmp/src/extract_fields.py fcmp/tests/fa4.json
```

It prints an annotated breakdown of every field — handy when investigating a specific tx or a
verification failure.

---

## Recap

- **Single-tx verification** (`--tx`) — one node read (the tree root); all crypto is offline. ✅
- **Continuous scanning** — fetches blocks from the node and verifies every FCMP++ proof,
  logging results. ✅
- **Building / relaying transactions** — not in this repo; see the **`mic_wallet`** project.
