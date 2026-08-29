""" Helios/Selene scalar multiplication in constant-time.
    python mic/fcmp/bindings/benchmarks/bench_ct.py [--reps 400]
"""

import argparse
import json
import os
import random
import time


from mic.fcmp.bindings import ct
from mic.fcmp.curve import WPoint, SELENE_B, SELENE_GX, SELENE_GY
from mic.fcmp.field import SeleneField

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def scalars():
    """Scalars a variable-time implementation would treat very differently."""
    rng = random.Random(1)
    sparse = 0
    for _ in range(8):  # 8 set bits, spread across 252 bits
        sparse |= 1 << rng.randrange(252)
    return [
        ("1 (one bit)", 1),
        ("2^251 (one high bit)", 1 << 251),
        ("2^252 - 1 (all ones)", (1 << 252) - 1),
        ("sparse 252-bit (8 bits set)", sparse),
        ("random 252-bit", rng.getrandbits(252) | (1 << 251)),
    ]


def time_interleaved(mul, ks, rounds):
    """Minimum seconds per scalar, timing every scalar once per round.

    Returns a list parallel to ks. See the module docstring for why minimum and
    why interleaved.
    """
    best = [float("inf")] * len(ks)
    for _ in range(rounds):
        for i, k in enumerate(ks):
            t = time.perf_counter()
            mul(k)
            dt = time.perf_counter() - t
            if dt < best[i]:
                best[i] = dt
    return best


def _stock_selene_mul(x, y):
    """k·P through the stock (variable-time) bindings, or None if absent."""
    try:
        # build.sh builds in place, so this lives in the package, not on sys.path.
        from mic.fcmp.bindings import helioselene_bindings as hb
    except ImportError:
        return None

    def mul(k):
        P = hb.SelenePoint()
        P.set_xy(f"{x:064x}", f"{y:064x}")
        return hb.Scalar(f"{k:064x}") * P

    return mul


def _measure(mul, rounds):
    labels = [lbl for lbl, _ in scalars()]
    ks = [k for _, k in scalars()]
    best = time_interleaved(mul, ks, rounds)
    rows = [{"scalar": lbl, "min_us": t * 1e6} for lbl, t in zip(labels, best)]
    lo, hi = min(best), max(best)
    return rows, (hi / lo if lo else float("inf"))


def main(argv=None):
    p = argparse.ArgumentParser(description="constant-time evidence for k·P")
    p.add_argument("--reps", type=int, default=400,
                   help="interleaved rounds; each round times every scalar once")
    p.add_argument("--compare", action="store_true",
                   help="also time the stock variable-time bindings, for contrast")
    p.add_argument("--out", default=os.path.join(RESULTS, "constant_time.json"))
    a = p.parse_args(argv)

    G = WPoint(SeleneField, SELENE_B, SELENE_GX, SELENE_GY)

    print(f"scalar-mult backend: {ct.backend()}")
    print(f"curve: Selene   rounds: {a.reps}   (minimum of interleaved rounds)\n")

    rows, spread = _measure(lambda k: G * k, a.reps)

    stock_rows = stock_spread = None
    if a.compare:
        stock_mul = _stock_selene_mul(G.x.v, G.y.v)
        if stock_mul is None:
            print("  (stock bindings not present, nothing to compare against)\n")
        else:
            stock_rows, stock_spread = _measure(stock_mul, a.reps)

    header = f"  {'scalar':<30} {'this (ladder)':>15}"
    if stock_rows:
        header += f" {'stock (wNAF)':>15}"
    print(header)
    for i, r in enumerate(rows):
        line = f"  {r['scalar']:<30} {r['min_us']:>13.0f} µs"
        if stock_rows:
            line += f" {stock_rows[i]['min_us']:>13.0f} µs"
        print(line)

    constant = spread < 1.10
    line = f"  {'spread (max/min)':<30} {spread:>13.2f} ×"
    if stock_spread:
        line += f" {stock_spread:>13.2f} ×"
    print("\n" + line)
    print(f"  => {'CONSTANT-TIME' if constant else 'VARIABLE-TIME, the scalar leaks'}")
    if stock_spread:
        print(f"     the stock bindings leak: {stock_spread:.1f}× spread across the same scalars")
    if not constant and not ct.HAVE_CT:
        print("     (build the bindings: bash mic/fcmp/bindings/build.sh)")

    out = {"backend": ct.backend(), "rounds": a.reps, "curve": "selene",
           "rows": rows, "spread": spread, "constant_time": constant,
           "stock_rows": stock_rows, "stock_spread": stock_spread}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\n-> {a.out}")
    return 0 if constant else 1


if __name__ == "__main__":
    raise SystemExit(main())
