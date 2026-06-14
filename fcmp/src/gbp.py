# MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

## Acknowledgments
# This project incorporates [`monero-oxide`](https://github.com/monero-oxide/monero-oxide), licensed under the [MIT License](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/LICENSE).

# Generalized Bulletproofs (GBP) – pure Python implementation.
#
# Translates:
#   scalar_vector.rs, point_vector.rs, lincomb.rs, lib.rs,
#   inner_product.rs, arithmetic_circuit_proof.rs
#
# All field and curve arithmetic is duck-typed: any field element F and curve
# point G work as long as they implement the standard arithmetic operators.

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from multiexp import multiexp


# ---------------------------------------------------------------------------
# ScalarVector  (scalar_vector.rs)
# ---------------------------------------------------------------------------

class ScalarVector:
    """Thin list wrapper over field elements with Bulletproofs arithmetic."""

    __slots__ = ("v",)

    def __init__(self, elems):
        self.v = list(elems)

    # --- Construction helpers ---

    @classmethod
    def zeros(cls, n, field_cls=None, sample=None):
        """Return a zero vector of length n.

        Provide either `field_cls` (used as `field_cls(0)`) or `sample`
        (a field element whose type is used).
        """
        if sample is not None:
            z = type(sample)(0)
        else:
            z = field_cls(0)
        return cls([z] * n)

    @classmethod
    def powers(cls, x, n):
        """Return [1, x, x^2, ..., x^{n-1}]."""
        if n == 0:
            return cls([])
        one = type(x)(1)
        if n == 1:
            return cls([one])
        res = [one, x]
        for i in range(2, n):
            res.append(res[-1] * x)
        return cls(res)

    # --- Sequence protocol ---

    def __len__(self):
        return len(self.v)

    def __getitem__(self, i):
        return self.v[i]

    def __setitem__(self, i, val):
        self.v[i] = val

    def __iter__(self):
        return iter(self.v)

    def is_empty(self):
        return len(self.v) == 0

    def clone(self):
        return ScalarVector(list(self.v))

    # --- Arithmetic with a scalar (broadcast) ---

    def __add__(self, other):
        if isinstance(other, ScalarVector):
            assert len(self.v) == len(other.v)
            return ScalarVector([a + b for a, b in zip(self.v, other.v)])
        return ScalarVector([a + other for a in self.v])

    def __sub__(self, other):
        if isinstance(other, ScalarVector):
            assert len(self.v) == len(other.v)
            return ScalarVector([a - b for a, b in zip(self.v, other.v)])
        return ScalarVector([a - other for a in self.v])

    def __mul__(self, other):
        if isinstance(other, ScalarVector):
            assert len(self.v) == len(other.v)
            return ScalarVector([a * b for a, b in zip(self.v, other.v)])
        return ScalarVector([a * other for a in self.v])

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __neg__(self):
        return ScalarVector([-a for a in self.v])

    def __iadd__(self, other):
        if isinstance(other, ScalarVector):
            for i, b in enumerate(other.v):
                self.v[i] = self.v[i] + b
        else:
            for i in range(len(self.v)):
                self.v[i] = self.v[i] + other
        return self

    def __isub__(self, other):
        if isinstance(other, ScalarVector):
            for i, b in enumerate(other.v):
                self.v[i] = self.v[i] - b
        else:
            for i in range(len(self.v)):
                self.v[i] = self.v[i] - other
        return self

    # --- Inner products ---

    def inner_product(self, other_iter):
        """Dot product.  other_iter is an iterator or list."""
        res = None
        other_iter = iter(other_iter)
        for a in self.v:
            b = next(other_iter, None)
            if b is None:
                break
            res = a * b if res is None else res + a * b
        return res

    def inner_product_without_length_checks(self, other_iter):
        """Dot product ignoring length mismatch; shorter side is zero-padded."""
        return self.inner_product(other_iter)

    def sum(self):
        res = None
        for a in self.v:
            res = a if res is None else res + a
        return res

    # --- Split ---

    def split(self, at):
        return ScalarVector(self.v[:at]), ScalarVector(self.v[at:])

    def extend(self, other_v):
        self.v.extend(other_v)
        return self

    def truncate(self, n):
        self.v = self.v[:n]
        return self


# ---------------------------------------------------------------------------
# PointVector  (point_vector.rs)
# ---------------------------------------------------------------------------

class PointVector:
    """Thin list wrapper over curve points with Bulletproofs arithmetic."""

    __slots__ = ("v",)

    def __init__(self, pts):
        self.v = list(pts)

    def __len__(self):
        return len(self.v)

    def __getitem__(self, i):
        return self.v[i]

    def is_empty(self):
        return len(self.v) == 0

    def clone(self):
        return PointVector(list(self.v))

    def split(self):
        """Split in half; panics if not even."""
        assert len(self.v) % 2 == 0
        mid = len(self.v) // 2
        return PointVector(self.v[:mid]), PointVector(self.v[mid:])

    def add_vec(self, other):
        assert len(self.v) == len(other.v)
        return PointVector([a + b for a, b in zip(self.v, other.v)])

    def sub_vec(self, other):
        assert len(self.v) == len(other.v)
        return PointVector([a - b for a, b in zip(self.v, other.v)])

    def mul_vec(self, sv):
        """Scale each point by corresponding scalar."""
        return PointVector([p * sv[i] for i, p in enumerate(self.v)])

    def multiexp(self, sv, identity):
        """Compute sum(sv[i] * v[i])."""
        pairs = list(zip(sv.v, self.v))
        return multiexp(pairs, identity)


# ---------------------------------------------------------------------------
# LinComb  (lincomb.rs)
# ---------------------------------------------------------------------------

def _accumulate_vector(acc_sv, sparse_weights, weight):
    """acc_sv += sparse_weights * weight.  Returns highest index written."""
    hi = 0
    for (i, coeff) in sparse_weights:
        acc_sv[i] = acc_sv[i] + coeff * weight
        hi = max(hi, i)
    return hi


class LinComb:
    """Sparse linear combination: WL·aL + WR·aR + WO·aO + WCG·CG + WV·V + c."""

    def __init__(self):
        self.highest_a_index = None
        self.highest_c_index = None
        self.highest_v_index = None
        self.WL  = []           # list of (index, field_elem)
        self.WR  = []
        self.WO  = []
        self.WCG = []           # list of lists of (index, field_elem)
        self.WV  = []
        self.c   = None         # constant; set when term() first called

    def _reconcile(self, other):
        self.highest_a_index = _max_opt(self.highest_a_index, other.highest_a_index)
        self.highest_c_index = _max_opt(self.highest_c_index, other.highest_c_index)
        self.highest_v_index = _max_opt(self.highest_v_index, other.highest_v_index)
        while len(self.WCG) < len(other.WCG):
            self.WCG.append([])

    @classmethod
    def empty(cls):
        return cls()

    def term(self, scalar, var):
        """Add `scalar * var` to this combination."""
        kind = var[0]
        if kind == "aL":
            i = var[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WL.append((i, scalar))
        elif kind == "aR":
            i = var[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WR.append((i, scalar))
        elif kind == "aO":
            i = var[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WO.append((i, scalar))
        elif kind == "CG":
            i, j = var[1], var[2]
            self.highest_c_index = _max_opt(self.highest_c_index, i)
            self.highest_a_index = _max_opt(self.highest_a_index, j)
            while len(self.WCG) <= i:
                self.WCG.append([])
            self.WCG[i].append((j, scalar))
        elif kind == "V":
            i = var[1]
            self.highest_v_index = _max_opt(self.highest_v_index, i)
            self.WV.append((i, scalar))
        else:
            raise ValueError(f"unknown variable kind {kind!r}")
        if self.c is None:
            self.c = scalar * type(scalar)(0)   # zero of the same type
        return self

    def constant(self, scalar):
        self.c = scalar if self.c is None else self.c + scalar
        return self

    def __add__(self, other):
        res = LinComb()
        res._reconcile(self)
        res._reconcile(other)
        res.WL  = self.WL  + other.WL
        res.WR  = self.WR  + other.WR
        res.WO  = self.WO  + other.WO
        res.WCG = [list(a) + list(b) for a, b in zip(res.WCG,
                   ([list(x) for x in self.WCG] + [[] for _ in range(len(other.WCG) - len(self.WCG))]))]
        # Simpler: merge WCG
        res.WCG = []
        for i in range(max(len(self.WCG), len(other.WCG))):
            a = self.WCG[i] if i < len(self.WCG) else []
            b = other.WCG[i] if i < len(other.WCG) else []
            res.WCG.append(list(a) + list(b))
        res.WV = self.WV + other.WV
        c_self  = self.c  if self.c  is not None else None
        c_other = other.c if other.c is not None else None
        if c_self is None:
            res.c = c_other
        elif c_other is None:
            res.c = c_self
        else:
            res.c = c_self + c_other
        return res

    def __sub__(self, other):
        neg = LinComb()
        neg.highest_a_index = other.highest_a_index
        neg.highest_c_index = other.highest_c_index
        neg.highest_v_index = other.highest_v_index
        neg.WL  = [(i, -w) for i, w in other.WL]
        neg.WR  = [(i, -w) for i, w in other.WR]
        neg.WO  = [(i, -w) for i, w in other.WO]
        neg.WCG = [[(j, -w) for j, w in row] for row in other.WCG]
        neg.WV  = [(i, -w) for i, w in other.WV]
        neg.c   = (-other.c) if other.c is not None else None
        return self + neg

    def __mul__(self, scalar):
        res = LinComb()
        res.highest_a_index = self.highest_a_index
        res.highest_c_index = self.highest_c_index
        res.highest_v_index = self.highest_v_index
        res.WL  = [(i, w * scalar) for i, w in self.WL]
        res.WR  = [(i, w * scalar) for i, w in self.WR]
        res.WO  = [(i, w * scalar) for i, w in self.WO]
        res.WCG = [[(j, w * scalar) for j, w in row] for row in self.WCG]
        res.WV  = [(i, w * scalar) for i, w in self.WV]
        res.c   = self.c * scalar if self.c is not None else None
        return res

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def eval(self, aL, aR, aO, c_vecs, v_vals):
        """Evaluate at witness (aL, aR, aO, c_vecs, v_vals). Returns field element."""
        res = self.c if self.c is not None else None

        def add_term(existing, new):
            return new if existing is None else existing + new

        for i, w in self.WL:
            res = add_term(res, w * (aL[i] if i < len(aL.v) else type(w)(0)))
        for i, w in self.WR:
            res = add_term(res, w * (aR[i] if i < len(aR.v) else type(w)(0)))
        for i, w in self.WO:
            res = add_term(res, w * (aO[i] if i < len(aO.v) else type(w)(0)))
        for ci, wrow in enumerate(self.WCG):
            if ci < len(c_vecs):
                gv = c_vecs[ci].g_values
                for j, w in wrow:
                    res = add_term(res, w * (gv[j] if j < len(gv) else type(w)(0)))
        for i, w in self.WV:
            if i < len(v_vals):
                res = add_term(res, w * v_vals[i].value)
        return res


def _max_opt(a, b):
    if a is None: return b
    if b is None: return a
    return max(a, b)


# ---------------------------------------------------------------------------
# Variable helper constructors
# ---------------------------------------------------------------------------

def aL(i): return ("aL", i)
def aR(i): return ("aR", i)
def aO(i): return ("aO", i)
def CG(commitment, index): return ("CG", commitment, index)
def V(i): return ("V", i)


# ---------------------------------------------------------------------------
# Pedersen commitments
# ---------------------------------------------------------------------------

class PedersenCommitment:
    """Opening of a Pedersen commitment: value * g + mask * h."""

    def __init__(self, value, mask):
        self.value = value
        self.mask  = mask

    def commit(self, g, h, identity):
        return multiexp([(self.value, g), (self.mask, h)], identity)


class PedersenVectorCommitment:
    """Opening of a Pedersen vector commitment: sum(g_values[i]*g_bold[i]) + mask*h."""

    def __init__(self, g_values, mask):
        self.g_values = list(g_values)
        self.mask = mask

    def commit(self, g_bold, h, identity):
        pairs = list(zip(self.g_values, g_bold)) + [(self.mask, h)]
        return multiexp(pairs, identity)


# ---------------------------------------------------------------------------
# Generators / ProofGenerators / BatchVerifier  (lib.rs)
# ---------------------------------------------------------------------------

class ProofGenerators:
    """A slice of the full Generators set (reduced to a power of two)."""

    def __init__(self, g, h, g_bold, h_bold, identity):
        self._g      = g
        self._h      = h
        self._g_bold = list(g_bold)
        self._h_bold = list(h_bold)
        self.identity = identity   # the identity point of this curve

    def len(self): return len(self._g_bold)
    def g(self):   return self._g
    def h(self):   return self._h
    def g_bold(self, i): return self._g_bold[i]
    def h_bold(self, i): return self._h_bold[i]
    def g_bold_slice(self): return self._g_bold
    def h_bold_slice(self): return self._h_bold


class Generators:
    """Full generator set (g, h, g_bold, h_bold, h_sum)."""

    def __init__(self, g, h, g_bold, h_bold, identity):
        assert len(g_bold) == len(h_bold)
        n = len(g_bold)
        assert n > 0 and (n & (n - 1)) == 0, "g_bold length must be a power of two"
        self._g      = g
        self._h      = h
        self._g_bold = list(g_bold)
        self._h_bold = list(h_bold)
        self.identity = identity

        # Precompute h_sum: running sum at each power of 2
        running = identity
        h_sum = []
        nxt = 1
        for i, h_pt in enumerate(h_bold):
            running = running + h_pt
            if (i + 1) == nxt:
                h_sum.append(running)
                nxt *= 2
        self._h_sum = h_sum

    def g(self): return self._g
    def h(self): return self._h
    def g_bold_slice(self): return self._g_bold
    def h_bold_slice(self): return self._h_bold

    @staticmethod
    def new_batch_verifier(n, field_cls):
        """Create an empty BatchVerifier for generators of size n."""
        z = field_cls(0)
        return BatchVerifier(z, z, [], [], [], [], field_cls)

    def reduce(self, generators):
        """Return ProofGenerators sliced to `generators` (rounded up to power of 2)."""
        if generators == 0:
            return None
        n = 1
        while n < generators:
            n *= 2
        if n > len(self._g_bold):
            return None
        return ProofGenerators(
            self._g, self._h,
            self._g_bold[:n], self._h_bold[:n],
            self.identity,
        )

    def verify(self, verifier):
        """Final batch verification: all scalar*point sums must equal identity."""
        pairs = [(verifier.g, self._g), (verifier.h, self._h)]
        for i, sc in enumerate(verifier.g_bold):
            if i < len(self._g_bold):
                pairs.append((sc, self._g_bold[i]))
        for i, sc in enumerate(verifier.h_bold):
            if i < len(self._h_bold):
                pairs.append((sc, self._h_bold[i]))
        for i, sc in enumerate(verifier.h_sum):
            if i < len(self._h_sum):
                pairs.append((sc, self._h_sum[i]))
        pairs.extend(verifier.additional)
        result = multiexp(pairs, self.identity)
        return result.is_identity()


class BatchVerifier:
    """Accumulates scalar*point claims; verified in one multiexp."""

    def __init__(self, g_sc, h_sc, g_bold_scs, h_bold_scs, h_sum_scs, additional, field_cls):
        self.g          = g_sc
        self.h          = h_sc
        self.g_bold     = list(g_bold_scs)
        self.h_bold     = list(h_bold_scs)
        self.h_sum      = list(h_sum_scs)
        self.additional = list(additional)    # [(scalar, point)]
        self.field_cls  = field_cls

    def _ensure_g_bold(self, n):
        z = self.field_cls(0)
        while len(self.g_bold) < n:
            self.g_bold.append(z)

    def _ensure_h_bold(self, n):
        z = self.field_cls(0)
        while len(self.h_bold) < n:
            self.h_bold.append(z)

    def _ensure_h_sum(self, n):
        z = self.field_cls(0)
        while len(self.h_sum) < n:
            self.h_sum.append(z)


# ---------------------------------------------------------------------------
# Inner-Product Argument  (inner_product.rs)
# ---------------------------------------------------------------------------

def _challenge_products(challenges, field_cls):
    """Compute all products of challenge/challenge_inv combinations.

    challenges: list of (x, x_inv) pairs
    Returns list of 2^len(challenges) field elements.
    Each products[i] is the product of x_j^(bit_j(i)) * x_j_inv^(1-bit_j(i))
    where bit ordering follows the Bulletproofs convention.
    """
    one = field_cls(1)
    n = 1 << len(challenges)
    products = [one] * n

    if challenges:
        products[0] = challenges[0][1]   # x_inv
        products[1] = challenges[0][0]   # x

        for j in range(1, len(challenges)):
            x, x_inv = challenges[j]
            slots = (1 << (j + 1)) - 1
            while slots > 0:
                products[slots]     = products[slots // 2] * x
                products[slots - 1] = products[slots // 2] * x_inv
                slots -= 2
    return products


class IpStatement:
    """Inner-product argument (Protocol 2 from Bulletproofs)."""

    def __init__(self, generators, h_bold_weights, u, P_point=None, verifier_weight=None):
        """
        generators     : ProofGenerators
        h_bold_weights : ScalarVector — per-h_bold scaling
        u              : field element — discrete log of the u-generator w.r.t. g
        P_point        : prover's P commitment (for prove mode)
        verifier_weight: random scalar (for verify mode)
        """
        self.generators      = generators
        self.h_bold_weights  = h_bold_weights
        self.u               = u
        self.P_point         = P_point
        self.verifier_weight = verifier_weight

    def prove(self, transcript, a, b, field_cls):
        """Run the IPA prover.

        transcript: ProverTranscript
        a, b      : ScalarVector witnesses
        field_cls : field class for challenge generation
        """
        gen  = self.generators
        u_pt = gen.g() * self.u.v
        iden = gen.identity

        g_bold = PointVector(list(gen.g_bold_slice()))
        h_bold = PointVector([gen.h_bold(i) * self.h_bold_weights[i].v
                               for i in range(len(self.h_bold_weights.v))])

        a = a.clone()
        b = b.clone()
        P = self.P_point

        while len(g_bold) > 1:
            split_at = _next_pow2(len(a.v)) // 2
            a1, a2 = a.split(split_at)
            b1, b2 = b.split(split_at)
            g_bold1, g_bold2 = g_bold.split()
            h_bold1, h_bold2 = h_bold.split()

            cl = b2.inner_product(iter(a1.v))
            cr = a2.inner_product(iter(b1.v))

            L_pairs = (list(zip(a1.v, g_bold2.v)) +
                       list(zip(b2.v, h_bold1.v)) +
                       [(cl, u_pt)])
            R_pairs = (list(zip(a2.v, g_bold1.v)) +
                       list(zip(b1.v, h_bold2.v)) +
                       [(cr, u_pt)])
            L = multiexp(L_pairs, iden)
            R = multiexp(R_pairs, iden)

            transcript.push_point(L)
            transcript.push_point(R)
            x     = transcript.challenge(field_cls)
            x_inv = x.inv()

            g_bold = PointVector([
                multiexp([(x_inv, g_bold1.v[i]), (x, g_bold2.v[i])], iden)
                for i in range(len(g_bold1.v))
            ])
            h_bold = PointVector([
                multiexp([(x, h_bold1.v[i]), (x_inv, h_bold2.v[i])], iden)
                for i in range(len(h_bold1.v))
            ])
            P = L * (x * x).v + P + R * (x_inv * x_inv).v

            a = a1 * x
            a2s = a2 * x_inv
            for i in range(len(a.v)):
                a.v[i] = a.v[i] + a2s.v[i]
            b = b1 * x_inv
            b2s = b2 * x
            for i in range(len(b.v)):
                b.v[i] = b.v[i] + b2s.v[i]

        transcript.push_scalar(a[0])
        transcript.push_scalar(b[0])

    def verify(self, verifier, transcript, field_cls, point_from_bytes):
        """Queue IPA proof for batch verification.

        verifier         : BatchVerifier
        transcript       : VerifierTranscript
        field_cls        : field class for challenge generation
        point_from_bytes : callable(bytes) → point (curve-specific deserialization)
        """
        gen = self.generators
        n   = gen.len()

        verifier._ensure_g_bold(n)
        verifier._ensure_h_bold(n)

        lr_len = 0
        while (1 << lr_len) < n:
            lr_len += 1

        weight = self.verifier_weight

        L_pts = []
        R_pts = []
        xs    = []
        for _ in range(lr_len):
            L_pts.append(transcript.read_point(point_from_bytes))
            R_pts.append(transcript.read_point(point_from_bytes))
            x = transcript.challenge(field_cls)
            xs.append(x)

        # batch inversion of all challenges
        x_invs = _batch_field_invert(xs, field_cls)

        challenges = list(zip(xs, x_invs))
        for (x, x_inv), L, R in zip(challenges, L_pts, R_pts):
            verifier.additional.append((weight * x * x, L))
            verifier.additional.append((weight * x_inv * x_inv, R))

        product_cache = _challenge_products(challenges, field_cls)

        a = transcript.read_scalar(field_cls)
        b = transcript.read_scalar(field_cls)
        c = a * b

        for i in range(len(gen.g_bold_slice())):
            verifier.g_bold[i] = verifier.g_bold[i] - weight * product_cache[i] * a

        for i in range(len(gen.h_bold_slice())):
            verifier.h_bold[i] = (verifier.h_bold[i] -
                                  weight * product_cache[len(product_cache) - 1 - i] *
                                  b * self.h_bold_weights[i])

        verifier.g = verifier.g - weight * c * self.u


# ---------------------------------------------------------------------------
# Arithmetic Circuit Proof  (arithmetic_circuit_proof.rs)
# ---------------------------------------------------------------------------

class ArithmeticCircuitWitness:
    """Witness for an arithmetic circuit statement.

    aL, aR: ScalarVectors (left and right inputs)
    aO    : ScalarVector  (aL * aR element-wise, computed here)
    c     : list of PedersenVectorCommitment openings
    v     : list of PedersenCommitment openings
    """

    def __init__(self, aL, aR, c, v):
        assert len(aL.v) == len(aR.v)
        if len(aL.v) == 0:
            # Pad to 1 if empty
            zero = c[0].g_values[0] * type(c[0].g_values[0])(0) if c and c[0].g_values else None
            if zero is None and v:
                zero = v[0].value * type(v[0].value)(0)
            aL = ScalarVector([zero])
            aR = ScalarVector([zero])
        aO = ScalarVector([al * ar for al, ar in zip(aL.v, aR.v)])
        self.aL = aL
        self.aR = aR
        self.aO = aO
        self.c  = list(c)
        self.v  = list(v)


class ArithmeticCircuitStatement:
    """GBP arithmetic circuit statement (prover and verifier)."""

    def __init__(self, generators, constraints, C_commitments, V_commitments):
        """
        generators    : ProofGenerators
        constraints   : list of LinComb
        C_commitments : list of points (vector commitment points)
        V_commitments : list of points (scalar commitment points)
        """
        self.generators    = generators
        self.constraints   = list(constraints)
        self.C             = list(C_commitments)
        self.V             = list(V_commitments)

    def n(self): return self.generators.len()
    def q(self): return len(self.constraints)
    def c(self): return len(self.C)
    def m(self): return len(self.V)

    # ---- yz challenge computation ----

    def _yz_challenges(self, y, z_1, field_cls):
        """Compute y_inv powers and z powers."""
        n = self.n()
        q = self.q()
        y_inv = ScalarVector.powers(y.inv(), n)
        z = ScalarVector([z_1])
        for _ in range(1, q):
            z.v.append(z.v[-1] * z_1)
        z.v = z.v[:q]
        return y_inv, z

    # ---- prove ----

    def prove(self, rng_fn, transcript, witness, field_cls):
        """Prove the statement.

        rng_fn     : callable() → field element (random scalar)
        transcript : ProverTranscript
        witness    : ArithmeticCircuitWitness
        field_cls  : field class for challenges
        """
        n = self.n()
        c = self.c()
        m = self.m()
        gen = self.generators
        iden = gen.identity

        assert len(witness.aL.v) <= n

        alpha = rng_fn()
        beta  = rng_fn()
        rho   = rng_fn()

        # AI = sum(aL[i]*g_bold[i]) + sum(aR[i]*h_bold[i]) + alpha*h
        AI_pairs = ([(al, gen.g_bold(i)) for i, al in enumerate(witness.aL.v)] +
                    [(ar, gen.h_bold(i)) for i, ar in enumerate(witness.aR.v)] +
                    [(alpha, gen.h())])
        AI = multiexp(AI_pairs, iden)

        # AO = sum(aO[i]*g_bold[i]) + beta*h
        AO_pairs = ([(ao, gen.g_bold(i)) for i, ao in enumerate(witness.aO.v)] +
                    [(beta, gen.h())])
        AO = multiexp(AO_pairs, iden)

        # S = sum(sL[i]*g_bold[i]) + sum(sR[i]*h_bold[i]) + rho*h
        sL = ScalarVector([rng_fn() for _ in range(n)])
        sR = ScalarVector([rng_fn() for _ in range(n)])
        S_pairs = ([(sl, gen.g_bold(i)) for i, sl in enumerate(sL.v)] +
                   [(sr, gen.h_bold(i)) for i, sr in enumerate(sR.v)] +
                   [(rho, gen.h())])
        S = multiexp(S_pairs, iden)

        transcript.push_point(AI)
        transcript.push_point(AO)
        transcript.push_point(S)
        y  = transcript.challenge(field_cls)
        z1 = transcript.challenge(field_cls)
        y_inv, z = self._yz_challenges(y, z1, field_cls)
        y_pow = ScalarVector.powers(y, n)

        ni  = 2 + 2 * (c // 2)
        ilr = ni // 2
        io  = ni
        is_ = ni + 1
        jlr = ni // 2
        jo  = 0
        js  = ni + 1

        zero_sv = ScalarVector.zeros(n, sample=y)
        l = [zero_sv.clone() for _ in range(is_ + 1)]
        r = [zero_sv.clone() for _ in range(is_ + 1)]

        # Build l_weights, r_weights, o_weights from constraints * z
        l_weights = zero_sv.clone()
        r_weights = zero_sv.clone()
        o_weights = zero_sv.clone()
        l_hi = r_hi = o_hi = 0
        for constraint, zk in zip(self.constraints, z.v):
            l_hi = max(l_hi, _accumulate_vector(l_weights, constraint.WL, zk))
            r_hi = max(r_hi, _accumulate_vector(r_weights, constraint.WR, zk))
            o_hi = max(o_hi, _accumulate_vector(o_weights, constraint.WO, zk))
        l_weights.truncate(l_hi + 1)
        r_weights.truncate(r_hi + 1)
        o_weights.truncate(o_hi + 1)

        # l[ilr] = r_weights * y_inv + aL
        l[ilr] = zero_sv.clone()
        for i in range(len(r_weights.v)):
            l[ilr][i] = r_weights[i] * y_inv[i]
        for i, al in enumerate(witness.aL.v):
            if i < len(l[ilr].v):
                l[ilr][i] = l[ilr][i] + al
            else:
                l[ilr].v.append(al)

        l[io] = witness.aO.clone()
        l[is_] = sL.clone()

        # r[jlr] = l_weights + aR * y
        r[jlr] = zero_sv.clone()
        for i in range(len(l_weights.v)):
            r[jlr][i] = l_weights[i]
        for i, ar in enumerate(witness.aR.v):
            ar_y = ar * y_pow[i]
            if i < len(r[jlr].v):
                r[jlr][i] = r[jlr][i] + ar_y
            else:
                r[jlr].v.append(ar_y)

        # r[jo] = o_weights - y_powers
        r[jo] = ScalarVector([type(y)(0)] * n)
        for i in range(len(o_weights.v)):
            r[jo][i] = o_weights[i] - y_pow[i]
        for i in range(len(o_weights.v), n):
            r[jo][i] = -y_pow[i]

        r[js] = sR * y_pow

        # Vector commitment terms
        for ci, vc in enumerate(witness.c):
            cg_weights = zero_sv.clone()
            cg_hi = 0
            for constraint, zk in zip(self.constraints, z.v):
                if ci < len(constraint.WCG):
                    cg_hi = max(cg_hi, _accumulate_vector(cg_weights, constraint.WCG[ci], zk))
            cg_weights.truncate(cg_hi + 1)

            i = ci
            if i >= ilr:
                i += 1
            j = ni - i

            l[i] = ScalarVector(list(vc.g_values))
            r[j] = cg_weights

        # t polynomial: t[i+j] += l[i] · r[j]
        t_len = 1 + 2 * (len(l) - 1)
        t = ScalarVector.zeros(t_len, sample=y)
        for i, li in enumerate(l):
            for j, rj in enumerate(r):
                t[i + j] = t[i + j] + li.inner_product(iter(rj.v))

        # tau masks
        tau_before = [rng_fn() for _ in range(ni)]
        tau_after  = [rng_fn() for _ in range(t_len - ni - 1)]

        # Commit to t (all except t[ni])
        for ti, tau in zip(t.v[:ni], tau_before):
            transcript.push_point(multiexp([(ti, gen.g()), (tau, gen.h())], iden))
        for ti, tau in zip(t.v[ni + 1:], tau_after):
            transcript.push_point(multiexp([(ti, gen.g()), (tau, gen.h())], iden))

        x_pow = ScalarVector.powers(transcript.challenge(field_cls), t_len)

        def poly_eval(poly):
            res = zero_sv.clone()
            for i, coeff in enumerate(poly):
                for k in range(len(coeff.v)):
                    res[k] = res[k] + coeff[k] * x_pow[i]
            return res

        l_eval = poly_eval(l)
        r_eval = poly_eval(r)
        t_caret = l_eval.inner_product(iter(r_eval.v))

        # V_weights for tau_x
        V_weights = ScalarVector.zeros(len(self.V), sample=y)
        for constraint, zk in zip(self.constraints, z.v):
            _accumulate_vector(V_weights, constraint.WV, -zk)

        # tau_x = sum of tau_poly[i] * x^i
        v_masks_ip = V_weights.inner_product(v.mask for v in witness.v)
        if v_masks_ip is None:
            v_masks_ip = type(y)(0)
        tau_poly = (tau_before + [v_masks_ip] + tau_after)
        tau_x = type(y)(0)
        for i, coeff in enumerate(tau_poly):
            tau_x = tau_x + coeff * x_pow[i]

        # u = alpha*x[ilr] + beta*x[io] + rho*x[is] + sum(c.mask * x[i'])
        u = alpha * x_pow[ilr] + beta * x_pow[io] + rho * x_pow[is_]
        for ci, vc in enumerate(witness.c):
            i = ci
            if i >= ni // 2:
                i += 1
            u = u + x_pow[i] * vc.mask

        transcript.push_scalar(tau_x)
        transcript.push_scalar(u)
        transcript.push_scalar(t_caret)
        ip_x = transcript.challenge(field_cls)

        # P = sum(l[i]*g_bold[i]) + sum(y_inv[i]*r[i]*h_bold[i]) + ip_x*t_caret*g
        P_pairs = ([(l_eval[i], gen.g_bold(i)) for i in range(len(l_eval.v))] +
                   [(y_inv[i] * r_eval[i], gen.h_bold(i)) for i in range(len(r_eval.v))] +
                   [(ip_x * t_caret, gen.g())])
        P_pt = multiexp(P_pairs, iden)

        IpStatement(gen, y_inv, ip_x, P_point=P_pt).prove(
            transcript, l_eval, r_eval, field_cls)

    # ---- verify ----

    def verify(self, rng_fn, verifier, transcript, field_cls, point_from_bytes):
        """Queue proof for batch verification.

        rng_fn           : callable() → field element (random scalar for batching)
        verifier         : BatchVerifier
        transcript       : VerifierTranscript
        field_cls        : field class for challenges
        point_from_bytes : callable(bytes) → point  (curve-specific deserialization)
        """
        n = self.n()
        c = self.c()
        gen = self.generators

        ni  = 2 + 2 * (c // 2)
        ilr = ni // 2
        io  = ni
        is_ = ni + 1
        jlr = ni // 2

        l_r_len  = 1 + ni + 1
        t_poly_len = 2 * l_r_len - 1

        verifier._ensure_g_bold(n)
        verifier._ensure_h_bold(n)

        def read_pt():
            return transcript.read_point(point_from_bytes)

        AI = read_pt()
        AO = read_pt()
        S  = read_pt()
        y  = transcript.challenge(field_cls)
        z1 = transcript.challenge(field_cls)
        y_inv, z = self._yz_challenges(y, z1, field_cls)

        zero_sv = ScalarVector.zeros(n, sample=y)
        l_weights = zero_sv.clone()
        r_weights = zero_sv.clone()
        o_weights = zero_sv.clone()
        for constraint, zk in zip(self.constraints, z.v):
            _accumulate_vector(l_weights, constraint.WL, zk)
            _accumulate_vector(r_weights, constraint.WR, zk)
            _accumulate_vector(o_weights, constraint.WO, zk)
        r_weights = r_weights * y_inv

        delta = r_weights.inner_product(iter(l_weights.v))

        T_before = [read_pt() for _ in range(ni)]
        T_after  = [read_pt() for _ in range(t_poly_len - ni - 1)]
        x_pow = ScalarVector.powers(transcript.challenge(field_cls), t_poly_len)

        tau_x  = transcript.read_scalar(field_cls)
        u      = transcript.read_scalar(field_cls)
        t_caret = transcript.read_scalar(field_cls)

        # First verification equation: tau_x*h + t_caret*g == rhs
        w1 = rng_fn()
        verifier.g = verifier.g + t_caret * w1
        verifier.h = verifier.h + tau_x  * w1

        V_weights = ScalarVector.zeros(len(self.V), sample=y)
        for constraint, zk in zip(self.constraints, z.v):
            _accumulate_vector(V_weights, constraint.WV, -zk)
        V_weights = V_weights * x_pow[ni]

        z_c_sum = z.inner_product(iter(
            constraint.c if constraint.c is not None else type(y)(0)
            for constraint in self.constraints
        ))
        if z_c_sum is None:
            z_c_sum = type(y)(0)   # empty constraints → zero
        verifier.g = verifier.g - w1 * x_pow[ni] * (delta - z_c_sum)

        for Vw, V_pt in zip(V_weights.v, self.V):
            verifier.additional.append((-w1 * Vw, V_pt))
        for i, T in enumerate(T_before):
            verifier.additional.append((-w1 * x_pow[i], T))
        for i, T in enumerate(T_after):
            verifier.additional.append((-w1 * x_pow[ni + 1 + i], T))

        # Second block: P constraint
        w2 = rng_fn()
        xw = x_pow * w2

        verifier.additional.append((xw[ilr], AI))
        verifier.additional.append((xw[io],  AO))
        verifier.additional.append((xw[is_], S))

        log2_n = 0
        while (1 << log2_n) != n:
            log2_n += 1
        verifier._ensure_h_sum(log2_n + 1)
        verifier.h_sum[log2_n] = verifier.h_sum[log2_n] - w2

        h_bold_scalars = l_weights * xw[jlr]
        for i, wr in enumerate((r_weights * xw[jlr]).v):
            verifier.g_bold[i] = verifier.g_bold[i] + wr
        h_bold_scalars = h_bold_scalars + o_weights * w2

        for ci in range(len(self.C)):
            cg = zero_sv.clone()
            for constraint, zk in zip(self.constraints, z.v):
                if ci < len(constraint.WCG):
                    _accumulate_vector(cg, constraint.WCG[ci], zk)

            i = ci
            C_pt = self.C[ci]
            WCG  = cg
            if i >= ni // 2:
                i += 1
            j = ni - i
            verifier.additional.append((xw[i], C_pt))
            h_bold_scalars = h_bold_scalars + WCG * xw[j]

        h_bold_scalars = h_bold_scalars * y_inv
        for i, sc in enumerate(h_bold_scalars.v):
            verifier.h_bold[i] = verifier.h_bold[i] + sc

        verifier.h = verifier.h - w2 * u

        ip_x = transcript.challenge(field_cls)
        verifier.g = verifier.g + w2 * ip_x * t_caret

        IpStatement(gen, y_inv, ip_x, verifier_weight=w2).verify(
            verifier, transcript, field_cls, point_from_bytes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _next_pow2(n):
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def _batch_field_invert(elems, field_cls):
    """Batch inversion using Montgomery's trick."""
    n = len(elems)
    if n == 0:
        return []
    prefix = [None] * n
    prefix[0] = elems[0]
    for i in range(1, n):
        prefix[i] = prefix[i - 1] * elems[i]
    inv_all = prefix[-1].inv()
    result = [None] * n
    for i in range(n - 1, 0, -1):
        result[i] = inv_all * prefix[i - 1]
        inv_all = inv_all * elems[i]
    result[0] = inv_all
    return result
