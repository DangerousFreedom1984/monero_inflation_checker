"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

redundancy.py - does the FCMP++ constraint system carry any redundant rows?

Run it with:

    python -m mic.fcmp.r1cs_analysis.redundancy            # the sweep
    python -m mic.fcmp.r1cs_analysis.redundancy --layers 4
    python -m mic.fcmp.r1cs_analysis.redundancy --no-histogram

The full argument, the results and the limits are in redundancy.md.
"""

import argparse
import collections
import time

from mic.fcmp import circuit as _circuit
from mic.fcmp.proof import Fcmp
from mic.fcmp.r1cs import to_sparse


# =========================================================================== #
#  capturing the real circuits
# =========================================================================== #


def capture_circuits(seed: int, layers: int, rng_seed: int = 1, token_seed: int = 4242):
    """Run a real Fcmp.prove and return both populated R1CS systems, C1 then C2.

    Circuit.statement is the seam every circuit passes through on its way to the
    proof engine, so wrapping it collects the systems with their witnesses
    intact. The wrapper comes off in the finally. Randomness is pinned, so the
    captured system is the same on every run.
    """
    from mic.tests.fcmp.test_end_to_end import PinnedRandomness, make_fixture

    fx = make_fixture(seed=seed, layers=layers)
    captured = []
    original = _circuit.Circuit.statement

    def patched(self, *a, **k):
        captured.append(self)
        return original(self, *a, **k)

    _circuit.Circuit.statement = patched
    try:
        with PinnedRandomness(token_seed):
            branches = fx.branches()      # the branch blinds are drawn here
            fx.root_bytes(branches)
            Fcmp.prove(rng_seed=rng_seed, params=fx.params, branches=branches)
    finally:
        _circuit.Circuit.statement = original

    systems = [c.cs for c in captured if c.prover_data is not None]
    if not systems:
        raise RuntimeError("no prover-mode circuit captured")
    return systems


def read(cs):
    """(rows, kinds, w, col_names, p) with zero coefficients dropped.

    to_sparse leaves a constant-wire entry of coefficient 0 on every mul row, an
    artifact of Lc carrying a constant term whether or not it is used. Every
    rule below reads the SUPPORT of a row, so a zero would make a mul row look
    as though it mentioned the constant wire. Drop them once, here.
    """
    sparse, z, _col_of, col_names = to_sparse(cs)
    p = cs.F.P

    def clean(d):
        return {c: int(v) % p for c, v in d.items() if int(v) % p}

    rows = [(clean(a), clean(b), clean(c)) for a, b, c in sparse]
    return rows, [r.kind for r in cs.rows()], [int(v) % p for v in z], col_names, p


def rref(rows, p):
    """Adding and subtracting equations until things fall out, in general.

    This is what turns x+y=5 and x-y=1 into x=3 and y=2. Sparse Gauss-Jordan
    mod p. Returns ({pivot_col: row_index}, [rows]).

    Every row comes back 1 at its own pivot and free of every other pivot, so a
    row of support one is immediately readable as a forced value, which is the
    whole of rule L's second half.
    """
    pivot_of, out = {}, []
    for r in rows:
        r = dict(r)
        for c in list(r):                       # eliminate the known pivots
            f = r.get(c)
            if not f or c not in pivot_of:
                continue
            for cc, vv in out[pivot_of[c]].items():
                nv = (r.get(cc, 0) - f * vv) % p
                if nv:
                    r[cc] = nv
                else:
                    r.pop(cc, None)
        r = {c: v for c, v in r.items() if v}
        if not r:
            continue                            # dependent row, nothing new
        piv = min(r)
        inv = pow(r[piv], p - 2, p)
        r = {c: (v * inv) % p for c, v in r.items()}
        for other in out:                       # back-substitute into the rest
            f = other.get(piv)
            if not f:
                continue
            for cc, vv in r.items():
                nv = (other.get(cc, 0) - f * vv) % p
                if nv:
                    other[cc] = nv
                else:
                    other.pop(cc, None)
        pivot_of[piv] = len(out)
        out.append(r)
    return pivot_of, out


# =========================================================================== #
#  the question: is any row implied by the others?
# =========================================================================== #


def rank_scan(rows, kinds, p):
    """Is any row implied by the others? A question about the rows alone.

    Two facts get measured, and the second explains the first.

      rank        the linear block's row rank. Short of the row count and some
                  linear row is a combination of the others, so it constrains
                  nothing the rest do not already, and deleting it would not
                  enlarge the solution set.
      unique      a column the row mentions and no OTHER linear row does. A row
                  owning one cannot be in the span of the others: every other
                  row has coefficient zero there, so any combination of them
                  does too, and this row does not. Full rank follows, and the
                  reason is structural rather than numerical.

    The mul rows are counted but not rank tested, because rank is a linear
    notion and a product row is not in the span of anything. What is checked is
    the analogous ownership: whether any two mul rows share a column at all.
    """
    lin = [a for (a, _b, _c), k in zip(rows, kinds) if k == "linear"]
    n_mul = sum(1 for k in kinds if k == "mul")

    counts = {}
    for r in lin:
        for c in r:
            counts[c] = counts.get(c, 0) + 1
    unique = sum(1 for r in lin if any(counts[c] == 1 for c in r))

    seen = {}
    for (a, b, c), k in zip(rows, kinds):
        if k != "mul":
            continue
        for d in (a, b, c):
            for col in d:
                seen[col] = seen.get(col, 0) + 1
    shared = sum(1 for (a, b, c), k in zip(rows, kinds) if k == "mul"
                 and any(seen[col] > 1 for d in (a, b, c) for col in d))

    return {"linear": len(lin), "rank": len(rref(lin, p)[1]), "unique": unique,
            "mul": n_mul, "mul_shared": shared}


def unique_histogram(rows, kinds, col_names):
    """Which KIND of column ends up unique, used by exactly one linear row.

    The claim above is that the unique columns are there because every wire is
    opened by a multiplication row, so a gadget pinning a fresh operand emits
    the only linear row that will ever mention it. If that is right, every
    unique column is an aL, aR or aO wire and none is a commitment slot. This
    counts them so the claim is checkable rather than asserted.
    """
    lin = [a for (a, _b, _c), k in zip(rows, kinds) if k == "linear"]
    counts = collections.Counter(c for r in lin for c in r)
    out = collections.Counter()
    for r in lin:
        for c in r:
            if counts[c] == 1:
                out[col_names[c][0]] += 1
                break
    return out


# =========================================================================== #
#  reporting
# =========================================================================== #


def report_rank(rk):
    dep = rk["linear"] - rk["rank"]
    print(f"    {rk['linear']} linear rows, rank {rk['rank']}, "
          f"{dep} implied by the others")
    print(f"      {rk['unique']}/{rk['linear']} own a column no other linear "
          f"row mentions")
    print(f"      {rk['mul']} mul rows, {rk['mul_shared']} sharing a column "
          f"with another mul row")


def report_histogram(hist):
    if hist:
        print("      unique columns by wire kind: "
              + ", ".join(f"{k} {v}" for k, v in hist.most_common()))


def redundant(reps):
    """The verdict, and it keys on rank alone.

    Rank short of the row count is exactly the condition for some linear row to
    lie in the span of the others. The unique-column count is the EXPLANATION
    for why the rank comes out full, not a second test: a matrix can be full
    rank with no unique column anywhere, and folding that count into the
    verdict would report such a system as redundant when it is not.
    """
    return any(rk["rank"] != rk["linear"] for _label, _layers, rk in reps)


# =========================================================================== #
#  the command line
# =========================================================================== #


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="python -m mic.fcmp.r1cs_analysis.redundancy",
        description="Does the FCMP++ R1CS carry any redundant rows? Rank over "
                    "the linear block, quantified over every input.")
    ap.add_argument("--layers", default="1,2,3,4,5,6,7,8", metavar="N[,N...]",
                    help="tree depth, or a comma-separated sweep (default 1-8)")
    ap.add_argument("--seed", type=int, default=1, help="fixture seed (default 1)")
    ap.add_argument("--no-histogram", action="store_true",
                    help="skip the unique-column breakdown")
    args = ap.parse_args(argv)

    from mic.tests.fcmp.test_end_to_end import _parse_layers
    try:
        depths = _parse_layers(args.layers)
    except ValueError as e:
        ap.error(f"--layers: {e}")

    t0 = time.time()
    collected = []
    for layers in depths:
        circuits = capture_circuits(args.seed, layers)
        print(f"\ncaptured {len(circuits)} circuit(s) from a real Fcmp.prove "
              f"at {layers} layers, seed {args.seed}")

        for cs, label in zip(circuits, ("C1 (Helios)", "C2 (Selene)")):
            rows, kinds, _w, col_names, p = read(cs)
            if not rows:
                print(f"\n  {label}: no rows at this depth")
                continue
            print(f"\n  {label}: {len(rows)} rows x {len(col_names)} columns")
            rk = rank_scan(rows, kinds, p)
            report_rank(rk)
            if not args.no_histogram:
                report_histogram(unique_histogram(rows, kinds, col_names))
            collected.append((label, layers, rk))

    bad = redundant(collected)
    if bad:
        print("\nREDUNDANT: some linear row is implied by the others")
    else:
        n = sum(rk["linear"] for _l, _y, rk in collected)
        uniq = all(rk["unique"] == rk["linear"] for _l, _y, rk in collected)
        print(f"\nNOT REDUNDANT: all {n} linear rows across "
              f"{len(collected)} circuit(s) are linearly independent, so no "
              f"linear row lies in the span of the other linear rows, at any "
              f"input   ({time.time() - t0:.1f}s)")
        if uniq:
            print("  every one of them owns a column no other linear row "
                  "mentions, which is why")
        print("  note: this is a statement about the linear block. A linear row "
              "can still be a\n  consequence of the mul rows, which rank does "
              "not see. See redundancy.md.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
