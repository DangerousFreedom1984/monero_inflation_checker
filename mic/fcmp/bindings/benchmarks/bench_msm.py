"""Time sum(k_i * P_i) per backend, across the term counts the protocol actually uses.

    python mic/fcmp/bindings/benchmarks/bench_msm.py [--terms 2,8,512] [--reps 20] [--curve selene]

Results land in mic/fcmp/bindings/benchmarks/results/msm.json and are summarized on stdout.
"""

import argparse
import json
import os
import platform
import random
import time

from mic.fcmp.bindings import ct
from mic.fcmp.curve import (
    HELIOS_B,
    HELIOS_GX,
    HELIOS_GY,
    SELENE_B,
    SELENE_GX,
    SELENE_GY,
    HeliosField,
    SeleneField,
    WPoint,
)
from mic.fcmp import multiexp as _mx

try:
    from mic.fcmp.bindings import helioselene_bindings as _hb
except ImportError:
    _hb = None

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

DEFAULT_TERMS = [2, 4, 8, 16, 64, 128, 256, 512, 2048]

CURVES = {
    "selene": (SeleneField, SELENE_B, SELENE_GX, SELENE_GY, _mx.multiexp_selene),
    "helios": (HeliosField, HELIOS_B, HELIOS_GX, HELIOS_GY, _mx.multiexp_helios),
}


def make_terms(n, field_cls, B, gx, gy, seed):
    """n (scalar, point) pairs with full-width scalars and distinct points.

    Points are small multiples of the generator. Distinctness matters: equal
    points would let a bucket method collapse work it would not get to collapse
    on real input.
    """
    rng = random.Random(seed)
    G = WPoint(field_cls, B, gx, gy)
    pairs = []
    P = G
    for _ in range(n):
        P = P + G
        pairs.append((field_cls(rng.randrange(1, field_cls.P)), P))
    return pairs


def _stock_multiexp(curve, pairs, identity):
    """sum(k_i * P_i) through the stock wNAF bindings, one EC_POINT_mul per term.

    This lives here rather than in multiexp.py because the engine no longer has a
    stock path: helioselene_ct is the only native backend it will use. The stock
    extension is still built, and this is the only thing that calls it, so that
    the comparison below stays honest.
    """
    F, B, _gx, _gy, _d = CURVES[curve]
    mk_point = _hb.SelenePoint if curve == "selene" else _hb.HeliosPoint

    result = None
    for s, pt in pairs:
        k = _mx._scalar_int(s)
        if k == 0 or pt.is_identity():
            continue
        bp = mk_point()
        bp.set_xy(f"{pt.x.v:064x}", f"{pt.y.v:064x}")
        term = _hb.Scalar(f"{k:064x}") * bp
        result = term if result is None else result + term

    if result is None:
        return identity
    xh = result.x()
    if xh.startswith("<"):  # OpenSSL prints infinity as <INF>
        return identity
    return WPoint(F, B, F(int(xh, 16)), F(int(result.y(), 16)))


def time_min(fn, rounds):
    """Minimum seconds over `rounds` calls. See the module docstring for why."""
    best = float("inf")
    for _ in range(rounds):
        t = time.perf_counter()
        fn()
        dt = time.perf_counter() - t
        if dt < best:
            best = dt
    return best


def backends(curve, field_cls, B, dispatch):
    """The backends available right now, as (label, callable) pairs.

    Each is forced rather than auto-detected, so one run compares all of them.
    _multiexp_pure is always available. The other two depend on what was built.
    """
    ident = WPoint.identity(field_cls, B)

    def pure(pairs):
        """_multiexp_pure with the native ladder hidden.

        Necessary, not decorative: WPoint.__mul__ silently uses the native ladder
        whenever it is built, so timing a "pure Python" path without disabling it
        measures the C++ one and reports it under the wrong name.
        """
        saved = ct.HAVE_CT
        ct.HAVE_CT = False
        try:
            return _mx._multiexp_pure(pairs, ident)
        finally:
            ct.HAVE_CT = saved

    out = [("pure Python", pure)]

    if _hb is not None:
        out.append(("stock wNAF", lambda pairs: _stock_multiexp(curve, pairs, ident)))

    if ct.HAVE_CT:
        out.append(("helioselene_ct", lambda pairs, _d=dispatch: _d(pairs, ident)))

    return out


def bench_curve(curve, terms, reps, verbose=True):
    field_cls, B, gx, gy, dispatch = CURVES[curve]
    bes = backends(curve, field_cls, B, dispatch)

    if verbose:
        print(f"\ncurve: {curve}   rounds: {reps}   (minimum of interleaved rounds)")
        header = f"  {'terms':>6}" + "".join(f" {lbl:>16}" for lbl, _ in bes)
        print(header)

    rows = []
    for n in terms:
        pairs = make_terms(n, field_cls, B, gx, gy, seed=1000 + n)
        row = {"terms": n}
        for label, fn in bes:
            # pure Python at large n is quadratic-ish in wall time, so skip it there
            # rather than sit for minutes on a number nobody needs.
            if label == "pure Python" and n > 256:
                row[label] = None
                continue
            secs = time_min(lambda f=fn, p=pairs: f(p), reps)
            row[label] = secs * 1e6
        rows.append(row)

        if verbose:
            line = f"  {n:>6}"
            for label, _ in bes:
                v = row[label]
                line += f" {'-':>16}" if v is None else f" {v:>13.0f} us"
            print(line)

    return [lbl for lbl, _ in bes], rows


def summarize(labels, rows):
    """Per-term-count speedup of helioselene_ct over the stock bindings.

    Note the ct column is whichever algorithm the dispatcher picked, Straus below
    STRAUS_MAX_TERMS and the bucket MSM above it, not one fixed method.
    """
    if "stock wNAF" not in labels or "helioselene_ct" not in labels:
        return None
    out = {}
    for r in rows:
        stock, msm = r.get("stock wNAF"), r.get("helioselene_ct")
        if stock and msm:
            out[r["terms"]] = stock / msm
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description="multiexp cost by term count and backend")
    p.add_argument("--terms", default=",".join(str(t) for t in DEFAULT_TERMS),
                   help="comma-separated term counts")
    p.add_argument("--reps", type=int, default=20, help="rounds per measurement")
    p.add_argument("--curve", default="both", choices=["selene", "helios", "both"])
    p.add_argument("--out", default=os.path.join(RESULTS, "msm.json"))
    a = p.parse_args(argv)

    terms = [int(t) for t in a.terms.split(",") if t.strip()]
    curves = ["selene", "helios"] if a.curve == "both" else [a.curve]

    print(f"backend: {ct.backend()}")
    print(f"stock bindings present: {_hb is not None}  (benchmark only)")

    out = {
        "backend": ct.backend(),
        "have_stock_bindings": _hb is not None,
        "rounds": a.reps,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "curves": {},
    }

    for curve in curves:
        labels, rows = bench_curve(curve, terms, a.reps)
        ratios = summarize(labels, rows)
        out["curves"][curve] = {"labels": labels, "rows": rows, "msm_over_stock": ratios}
        if ratios:
            print(f"\n  helioselene_ct over stock wNAF, {curve}:")
            for n, r in ratios.items():
                print(f"    {n:>6} terms: {r:>6.2f}x")

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\n-> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
