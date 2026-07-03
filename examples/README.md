# Examples

Runnable, **instance-specific** demonstrations. These are deliberately kept out of
the general library modules (`v1/`, `fcmp/src/`, ...) so that those modules stay
generic and free of hardcoded wallets, transaction ids, or demo `print()` output.

| Script | What it shows | Needs |
|--------|---------------|-------|
| `example_v1_ring_signature.py` | Generate a v1 ring signature and verify it (offline round-trip) | nothing |
| `example_decode_address.py` | Decode a base58 Monero address into its public keys | an address (arg) |
| `example_scan_output.py` | Scan a tx and open a wallet-owned output | a node |
| `example_build_tx.py` | Build (optionally relay) an FCMP++ transaction | a node |

Run any of them with the project's virtualenv, e.g.:

```
python examples/example_v1_ring_signature.py
```
