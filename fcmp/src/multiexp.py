# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments
# This project incorporates [`monero-oxide`](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

# Fast multiexp over Selene / Helios via C++ OpenSSL bindings.
# Falls back to pure-Python Jacobian arithmetic if bindings are unavailable.

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

try:
    import helioselene_bindings as _hb
    _HAVE_BINDINGS = True
except ImportError:
    _HAVE_BINDINGS = False

from curve import (
    WPoint,
    HeliosField, HelioseleneField,
    HELIOS_B, SELENE_B,
)


# ---------------------------------------------------------------------------
# WPoint ↔ binding conversion helpers
# ---------------------------------------------------------------------------

def _wp_to_selene_binding(pt: WPoint):
    """WPoint (Selene, base field = HelioseleneField) → hb.SelenePoint."""
    bp = _hb.SelenePoint()
    bp.set_xy(f"{pt.x.v:064x}", f"{pt.y.v:064x}")
    return bp


def _wp_to_helios_binding(pt: WPoint):
    """WPoint (Helios, base field = HeliosField) → hb.HeliosPoint."""
    bp = _hb.HeliosPoint()
    bp.set_xy(f"{pt.x.v:064x}", f"{pt.y.v:064x}")
    return bp


def _selene_binding_to_wp(bp) -> WPoint:
    """hb.SelenePoint → WPoint."""
    x_hex = bp.x()
    y_hex = bp.y()
    if x_hex.startswith("<"):          # infinity
        return WPoint.identity(HelioseleneField, SELENE_B)
    x = HelioseleneField(int(x_hex, 16))
    y = HelioseleneField(int(y_hex, 16))
    return WPoint(HelioseleneField, SELENE_B, x, y)


def _helios_binding_to_wp(bp) -> WPoint:
    """hb.HeliosPoint → WPoint."""
    x_hex = bp.x()
    y_hex = bp.y()
    if x_hex.startswith("<"):
        return WPoint.identity(HeliosField, HELIOS_B)
    x = HeliosField(int(x_hex, 16))
    y = HeliosField(int(y_hex, 16))
    return WPoint(HeliosField, HELIOS_B, x, y)


# ---------------------------------------------------------------------------
# Fast multiexp using bindings
# ---------------------------------------------------------------------------

def _scalar_int(s) -> int:
    return s.v if hasattr(s, "v") else int(s)


def multiexp_selene(pairs, identity: WPoint) -> WPoint:
    """Compute sum(k_i * P_i) for Selene points using C++ bindings.

    pairs    : iterable of (scalar, WPoint) where WPoint is on Selene
    identity : WPoint identity element to return for empty/all-zero input
    """
    if _HAVE_BINDINGS:
        result_bp = None
        for scalar, pt in pairs:
            k = _scalar_int(scalar)
            if k == 0 or pt.is_identity():
                continue
            k_bp = _hb.Scalar(f"{k:064x}")
            term_bp = k_bp * _wp_to_selene_binding(pt)
            if result_bp is None:
                result_bp = term_bp
            else:
                result_bp = result_bp + term_bp
        if result_bp is None:
            return identity
        return _selene_binding_to_wp(result_bp)
    else:
        return _multiexp_pure(pairs, identity)


def multiexp_helios(pairs, identity: WPoint) -> WPoint:
    """Compute sum(k_i * P_i) for Helios points using C++ bindings.

    pairs    : iterable of (scalar, WPoint) where WPoint is on Helios
    identity : WPoint identity element to return for empty/all-zero input
    """
    if _HAVE_BINDINGS:
        result_bp = None
        for scalar, pt in pairs:
            k = _scalar_int(scalar)
            if k == 0 or pt.is_identity():
                continue
            k_bp = _hb.Scalar(f"{k:064x}")
            term_bp = k_bp * _wp_to_helios_binding(pt)
            if result_bp is None:
                result_bp = term_bp
            else:
                result_bp = result_bp + term_bp
        if result_bp is None:
            return identity
        return _helios_binding_to_wp(result_bp)
    else:
        return _multiexp_pure(pairs, identity)


# ---------------------------------------------------------------------------
# Pure-Python fallback
# ---------------------------------------------------------------------------

def _multiexp_pure(pairs, identity: WPoint) -> WPoint:
    result = None
    for scalar, pt in pairs:
        k = _scalar_int(scalar)
        if k == 0 or pt.is_identity():
            continue
        term = pt * k
        result = term if result is None else result + term
    return identity if result is None else result


# ---------------------------------------------------------------------------
# Curve-agnostic wrapper (detects field_cls from the first non-identity point)
# ---------------------------------------------------------------------------

def multiexp(pairs, identity: WPoint) -> WPoint:
    """Dispatch to multiexp_selene or multiexp_helios based on point type."""
    pairs = list(pairs)
    for _, pt in pairs:
        if not pt.is_identity():
            if pt.field_cls is HelioseleneField:
                return multiexp_selene(pairs, identity)
            else:
                return multiexp_helios(pairs, identity)
    return identity
