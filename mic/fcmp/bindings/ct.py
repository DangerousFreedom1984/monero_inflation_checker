"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Constant-time scalar multiplication on Helios/Selene, plus a bucket-method MSM.

Wraps helioselene_ct.cpp, built by build.sh. This is the binding used in this project.

Without the compiled module, it falls back to the pure-Python arithmetic, which is not constant-time. 

backend() reports which path is in use
"""

SELENE = "selene"
HELIOS = "helios"

try:
    from mic.fcmp.bindings import helioselene_ct as _ct

    HAVE_CT = True
except ImportError:  # not built - see build.sh
    _ct = None
    HAVE_CT = False


def backend() -> str:
    """Which arithmetic is live, for reporting.
    """
    if HAVE_CT:
        return "helioselene_ct (constant-time ladder + native MSM)"
    return "pure Python (VARIABLE-TIME double-and-add)"


def _hex(v) -> str:
    return f"{int(v):064x}"


def _point(curve: str):
    return _ct.SelenePoint() if curve == SELENE else _ct.HeliosPoint()


def _to_binding(curve: str, x: int, y: int):
    p = _point(curve)
    p.set_xy(_hex(x), _hex(y))
    return p


def _from_binding(p) -> tuple | None:
    xh = p.x()
    if xh.startswith("<"):  # OpenSSL prints infinity as <INF>
        return None
    return int(xh, 16), int(p.y(), 16)


def scalar_mul(curve: str, k: int, x: int, y: int) -> tuple | None:
    """Constant-time k*P for P = (x, y) on curve.

    Returns (x, y) ints, None for the identity, or None if the module is absent,
    so callers check HAVE_CT first to tell the two apart. 
    """
    if not HAVE_CT:
        return None
    k = int(k)
    if k == 0:
        return None
    return _from_binding(_ct.Scalar(_hex(k)) * _to_binding(curve, x, y))


def msm(curve: str, terms) -> tuple | None:
    """Sum of k_i*P_i by the bucket method, for public scalars only.

    terms is an iterable of (k, x, y) integer triples. Returns (x, y), or None for
    the identity and when the module is absent. 
    """
    if not HAVE_CT:
        return None
    ks, xs, ys = [], [], []
    for k, x, y in terms:
        k = int(k)
        if k == 0:
            continue
        ks.append(_hex(k))
        xs.append(_hex(x))
        ys.append(_hex(y))
    if not ks:
        return None
    fn = _ct.selene_msm if curve == SELENE else _ct.helios_msm
    return _from_binding(fn(ks, xs, ys))


def straus(curve: str, terms) -> tuple | None:
    """Sum of k_i*P_i by interleaved wNAF, for public scalars only.
    """
    if not HAVE_CT:
        return None
    ks, xs, ys = [], [], []
    for k, x, y in terms:
        k = int(k)
        if k == 0:
            continue
        ks.append(_hex(k))
        xs.append(_hex(x))
        ys.append(_hex(y))
    if not ks:
        return None
    fn = _ct.selene_straus if curve == SELENE else _ct.helios_straus
    return _from_binding(fn(ks, xs, ys))
