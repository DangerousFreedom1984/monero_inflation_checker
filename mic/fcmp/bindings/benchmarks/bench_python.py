"""Time this implementation's prove and verify, at the same tree depths the
reference benchmark uses.

    python mic/fcmp/bindings/benchmarks/bench_python.py [--layers 1,3,8] [--reps 5]

Results land in mic/fcmp/bindings/benchmarks/results/python.json and are summarized on stdout.
"""

import argparse
import json
import os
import platform
import statistics
import time


from mic.fcmp.bindings import ct
from mic.fcmp.proof import Fcmp
from mic.tests.fcmp.test_end_to_end import make_fixture, verify_membership

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def _median_ms(times):
    return statistics.median(times) * 1000.0


def bench_layers(layers, reps, verbose=True):
    """Time setup / prove / verify at one tree depth."""
    fx = make_fixture(seed=100 + layers, layers=layers)

    setup, prove, verify = [], [], []
    proof_len = None
    for _ in range(reps):
        t = time.perf_counter()
        bwb = fx.branches()                     # the EC divisors live here
        root = fx.root_bytes(bwb)
        setup.append(time.perf_counter() - t)

        t = time.perf_counter()
        mp = Fcmp.prove(rng_seed=1, params=fx.params, branches=bwb)
        prove.append(time.perf_counter() - t)
        proof_len = len(mp.proof)

        t = time.perf_counter()
        ok, detail = verify_membership(
            mp.proof, mp.root_blind_pok, fx.params, fx.is_c1, root, fx.layers,
            fx.verify_inputs(),
        )
        verify.append(time.perf_counter() - t)
        if not ok:
            raise SystemExit(f"benchmark proof failed to verify at {layers} layers: {detail}")

    row = {
        "layers": layers,
        "reps": reps,
        "proof_bytes": proof_len,
        "proof_bytes_with_pok": proof_len + 64,
        "blinds_ms": _median_ms(setup),
        "prove_ms": _median_ms(prove),
        "verify_ms": _median_ms(verify),
    }
    if verbose:
        print(f"  layers={layers:<2} proof={row['proof_bytes']:>5} B  "
              f"blinds={row['blinds_ms']:>7.0f} ms  prove={row['prove_ms']:>7.0f} ms  "
              f"verify={row['verify_ms']:>6.0f} ms")
    return row


def main(argv=None):
    p = argparse.ArgumentParser(description="benchmark this FCMP++ implementation")
    p.add_argument("--layers", default="1,3,8", help="comma-separated tree depths")
    p.add_argument("--reps", type=int, default=5, help="repetitions per depth (median reported)")
    p.add_argument("--out", default=os.path.join(RESULTS, "python.json"))
    a = p.parse_args(argv)

    layer_counts = [int(x) for x in a.layers.split(",") if x.strip()]

    print("this implementation (pure Python + OpenSSL bindings)")
    print(f"  scalar-mult backend: {ct.backend()}")
    print(f"  {platform.python_implementation()} {platform.python_version()} on "
          f"{platform.machine()}")
    print()
    rows = [bench_layers(n, a.reps) for n in layer_counts]

    out = {
        "implementation": "monero_inflation_checker_deliver",
        "backend": ct.backend(),
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "machine": platform.machine(),
        "rows": rows,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\n-> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
