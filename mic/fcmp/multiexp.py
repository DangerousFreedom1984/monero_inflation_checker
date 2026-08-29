"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Multiexponentiation over Selene / Helios: sum of k_i * P_i.

This code may not use the constant-time ladder, so its running time depends on
the scalars it is given. Verification passes only public values through it
(so it is fine) but proving passes the witness (private values).

There are two backends:

  1. helioselene_ct, which is the binding to the C++ code using OpenSSL. It has
     two algorithms for the multiexponentiation and each is activated depending on the
     term count (STRAUS_MAX_TERMS). 
  2. pure Python, _multiexp_pure below, the bucket method over projective
     coordinates with a single inversion at the end.
"""

from mic.fcmp.bindings import ct
from mic.fcmp.curve import (
    HELIOS,
    SELENE,
    WPoint,
    ProjectivePoint,
    SeleneField,
)

# ---------------------------------------------------------------------------
# Native multiexp
# ---------------------------------------------------------------------------


def _scalar_int(s) -> int:
    v = getattr(s, "v", None)
    return v if v is not None else int(s)


STRAUS_MAX_TERMS = 48


def _dispatch(curve, pairs, identity: WPoint) -> WPoint:
    """Shared body of multiexp_selene / multiexp_helios.

    curve is a ct.SELENE / ct.HELIOS tag. The two public wrappers differ only in
    which one they pass.
    """
    terms = []
    for s, p in pairs:
        k = _scalar_int(s)
        if k and not p.is_identity():
            terms.append((k, p))

    if not terms:
        return identity

    if not ct.HAVE_CT:
        return _multiexp_pure(terms, identity)

    fn = ct.straus if len(terms) <= STRAUS_MAX_TERMS else ct.msm
    res = fn(curve, ((k, p.x.v, p.y.v) for k, p in terms))
    if res is None:
        return identity
    F, B = identity.field_cls, identity.B
    return WPoint(F, B, F(res[0]), F(res[1]))


def multiexp_selene(pairs, identity: WPoint) -> WPoint:
    """Compute sum(k_i * P_i) for Selene points.

    pairs    : iterable of (scalar, WPoint) where WPoint is on Selene
    identity : WPoint identity element to return for empty/all-zero input
    """
    return _dispatch(ct.SELENE, pairs, identity)


def multiexp_helios(pairs, identity: WPoint) -> WPoint:
    """Compute sum(k_i * P_i) for Helios points.

    pairs    : iterable of (scalar, WPoint) where WPoint is on Helios
    identity : WPoint identity element to return for empty/all-zero input
    """
    return _dispatch(ct.HELIOS, pairs, identity)


# ---------------------------------------------------------------------------
# Pure-Python fallback
# ---------------------------------------------------------------------------


def _pure_window(n: int) -> int:
    """Bucket width for n terms, sized so the bucket array stays near n.

    Aggregating a window walks every bucket index, which in Python is real time
    rather than a few instructions, so a wide window is worse here than it is in
    C++ even though it needs fewer of them.
    """
    return max(2, min(8, max(1, n).bit_length() - 1))


def _multiexp_pure(pairs, identity: WPoint) -> WPoint:
    """Bucket-method multiexp over projective coordinates.

    The obvious version, one `pt * k` per term summed with affine adds, costs two
    modular exponentiations per term: one to leave Jacobian coordinates inside
    WPoint.__mul__ and one for the slope of the affine addition. Both are spent
    re-entering a representation the next step immediately leaves again.
    """
    terms = []
    for scalar, pt in pairs:
        k = _scalar_int(scalar)
        if k and not pt.is_identity():
            terms.append((k, pt))
    if not terms:
        return identity

    F, B = identity.field_cls, identity.B
    curve = SELENE if F is SeleneField else HELIOS

    def _finish(acc):
        if acc is None or acc.is_identity():
            return identity
        x, y = acc.to_affine()  # the one and only inversion
        return WPoint(F, B, F(x), F(y))

    # Below three terms the bucket bookkeeping costs more than it saves, so fall
    # back to double-and-add. Still projective, so still one inversion overall.
    if len(terms) <= 2:
        acc = None
        for k, p in terms:
            t = ProjectivePoint(p.x.v, p.y.v, 1, curve) * k
            acc = t if acc is None else acc + t
        return _finish(acc)

    c = _pure_window(len(terms))
    mask = (1 << c) - 1
    nwin = (max(k.bit_length() for k, _ in terms) + c - 1) // c

    pts = [ProjectivePoint(p.x.v, p.y.v, 1, curve) for _, p in terms]

    res = None
    for w in range(nwin - 1, -1, -1):
        if res is not None:
            for _ in range(c):
                res = res.double()

        buckets = {}
        shift = w * c
        for i, (k, _) in enumerate(terms):
            d = (k >> shift) & mask
            if d:
                b = buckets.get(d)
                buckets[d] = pts[i] if b is None else b + pts[i]
        if not buckets:
            continue

        # Running-sum aggregation: sum(d * bucket[d]) without multiplying.
        running = acc = None
        for j in range(max(buckets), 0, -1):
            b = buckets.get(j)
            if b is not None:
                running = b if running is None else running + b
            if running is not None:
                acc = running if acc is None else acc + running
        res = acc if res is None else res + acc

    return _finish(res)


# ---------------------------------------------------------------------------
# Curve-agnostic wrapper (detects field_cls from the first non-identity point)
# ---------------------------------------------------------------------------


def multiexp(pairs, identity: WPoint) -> WPoint:
    """Dispatch to multiexp_selene or multiexp_helios based on point type."""
    pairs = list(pairs)
    for _, pt in pairs:
        if not pt.is_identity():
            if pt.field_cls is SeleneField:
                return multiexp_selene(pairs, identity)
            else:
                return multiexp_helios(pairs, identity)
    return identity
