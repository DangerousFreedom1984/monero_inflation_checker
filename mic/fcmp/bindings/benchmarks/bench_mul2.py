"""Python side of the mul2.rs benchmark.

mul2.rs times k*G on Helios and Selene with the monero-oxide `helioselene` crate,
over 100 fixed scalars per curve, 100 rounds each, and then checks every result
against a fixed table of affine coordinates. This runs the very same vectors
through the C++ constant time bindings so the two numbers can be put side by side.

The vectors are parsed out of mul2.rs itself, so the two benchmarks cannot drift
apart.

    python mic/fcmp/bindings/benchmarks/bench_mul2.py [--rounds 100]

Two paths are timed:

  api     ct.scalar_mul, exactly what the rest of the project calls. Every call
          formats the scalar and the point as hex and rebuilds the OpenSSL point,
          so this is native multiplication plus the marshalling around it.
  core    the multiplication alone, with the Scalar and the point built once up
          front. This is the number to compare against Rust, which also keeps its
          scalars and its generator in native form across the loop.
"""

import argparse
import json
import os
import re
import time

from mic.fcmp.bindings import ct
from mic.fcmp.curve import HELIOS_GX, HELIOS_GY, SELENE_GX, SELENE_GY

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
MUL2 = os.path.join(HERE, "mul2.rs")

GENERATORS = {
    ct.HELIOS: (int(HELIOS_GX.v), int(HELIOS_GY.v)),
    ct.SELENE: (int(SELENE_GX.v), int(SELENE_GY.v)),
}

_HEX32 = r"[0-9a-fA-F]{64}"


def _const(src: str, name: str) -> str:
    """The body of a `const NAME ... = [ ... ];` item in mul2.rs."""
    start = src.index("const " + name)
    return src[start:src.index("];", start)]


def vectors(path: str = MUL2) -> dict:
    """The scalars and the expected affine results, read straight from mul2.rs."""
    with open(path) as f:
        src = f.read()

    out = {}
    for curve, prefix in ((ct.HELIOS, "HELIOS"), (ct.SELENE, "SELENE")):
        scalars = re.findall(f'"({_HEX32})"', _const(src, prefix + "_SCALARS_HEX"))
        results = re.findall(
            rf'\(\s*"({_HEX32})"\s*,\s*"({_HEX32})"\s*\)', _const(src, prefix + "_RESULT")
        )
        if len(scalars) != len(results):
            raise SystemExit(f"{prefix}: {len(scalars)} scalars but {len(results)} results")
        out[curve] = (
            [int(h, 16) for h in scalars],
            [(int(x, 16), int(y, 16)) for x, y in results],
        )
    return out


def check(curve: str, scalars, expected) -> None:
    """Every k*G against the table mul2.rs asserts on. Raises on the first miss."""
    gx, gy = GENERATORS[curve]
    for i, (k, want) in enumerate(zip(scalars, expected)):
        got = ct.scalar_mul(curve, k, gx, gy)
        if got != want:
            raise SystemExit(f"{curve} vector {i}: k={k:#x}\n  got  {got}\n  want {want}")


def time_api(curve: str, scalars, rounds: int) -> float:
    """Seconds for rounds x scalars muls through ct.scalar_mul."""
    gx, gy = GENERATORS[curve]
    mul = ct.scalar_mul
    t = time.perf_counter()
    for _ in range(rounds):
        for k in scalars:
            mul(curve, k, gx, gy)
    return time.perf_counter() - t


def time_core(curve: str, scalars, rounds: int) -> float:
    """Seconds for rounds x scalars muls with the native objects built up front."""
    binding = ct._ct
    gx, gy = GENERATORS[curve]
    g = binding.SelenePoint() if curve == ct.SELENE else binding.HeliosPoint()
    g.set_xy(f"{gx:064x}", f"{gy:064x}")
    ks = [binding.Scalar(f"{k:064x}") for k in scalars]
    t = time.perf_counter()
    for _ in range(rounds):
        for k in ks:
            k * g
    return time.perf_counter() - t


def main(argv=None):
    p = argparse.ArgumentParser(description="mul2.rs vectors through the C++ CT bindings")
    p.add_argument("--rounds", type=int, default=100,
                   help="rounds over the whole scalar set, as in mul2.rs (default 100)")
    p.add_argument("--out", default=os.path.join(RESULTS, "mul2_bindings.json"))
    a = p.parse_args(argv)

    if not ct.HAVE_CT:
        raise SystemExit("helioselene_ct is not built: bash mic/fcmp/bindings/build.sh")

    vecs = vectors()
    print("Helios / Selene Scalar Multiplication Benchmark (C++ constant-time bindings)")
    print(f"backend: {ct.backend()}")
    n = len(vecs[ct.HELIOS][0])
    print(f"vectors: {n} scalars per curve from mul2.rs, {a.rounds} rounds\n")

    rows = {}
    for curve in (ct.HELIOS, ct.SELENE):
        scalars, expected = vecs[curve]
        check(curve, scalars, expected)
        muls = a.rounds * len(scalars)
        api = time_api(curve, scalars, a.rounds)
        core = time_core(curve, scalars, a.rounds)
        rows[curve] = {"muls": muls, "api_s": api, "core_s": core,
                       "api_ms_per_mul": api / muls * 1e3,
                       "core_ms_per_mul": core / muls * 1e3}
        print(f"{curve.capitalize()}: {core:.4f} seconds  (core)   {api:.4f} seconds  (api)")
        print(f"Average per mul   : {core / muls * 1e3:.3f} ms (core)   "
              f"{api / muls * 1e3:.3f} ms (api)")
        print(f"  all {len(scalars)} vectors match the mul2.rs table\n")

    out = {"backend": ct.backend(), "rounds": a.rounds, "source": MUL2, "curves": rows}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"-> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
