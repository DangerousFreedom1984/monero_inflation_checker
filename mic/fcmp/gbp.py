"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Generalized Bulletproofs (GBP).

Serves both Helios and Selene.

Weight accumulation folds the
R1CS rows into a single set of coefficients on aL, aR, and aO using powers of a
challenge z. IpStatement proves the inner-product relation over the folded
vectors, and ArithmeticCircuitStatement builds the circuit proof on top of
IpStatement.

ProverTranscript and VerifierTranscript are the Fiat-Shamir state both proof
halves share. The prover writes into one and the verifier reads a proof back through
the other. In the end both derive the same challenges.

The pieces build on each other. ScalarVector and PointVector are thin list
wrappers. ScalarVector over field elements such as the witness vectors aL and aR and 
PointVector over curve points such as the generator lists g_bold and h_bold. Above
them sit the Pedersen openings, the Generators set that supplies g, h, g_bold,
h_bold, and h_sum and the BatchVerifier that gathers every scalar times point
claim so a whole proof settles in one multiexp. 

"""

import hashlib

from mic.fcmp.curve import point_to_bytes
from mic.fcmp.multiexp import multiexp
from mic.fcmp.r1cs import KIND_AL, KIND_AR, KIND_AO, KIND_CG, KIND_V


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------
# Mirrors generalized_bulletproofs::transcript. The prover folds every scalar and
# point it sends into a running Blake2b state and into the proof buffer. The
# verifier replays that same state as it reads the proof back, so both sides
# derive identical challenges.

SCALAR = 0
POINT = 1
CHALLENGE = 2


class ProverTranscript:
    """Mirrors generalized_bulletproofs::transcript::Transcript."""

    def __init__(self, context: bytes):
        if len(context) != 32:
            raise ValueError(f"transcript context must be 32 bytes, got {len(context)}")
        self._digest = hashlib.blake2b(digest_size=64)
        self._digest.update(context)
        self._buf = bytearray()

    def push_scalar(self, field_element) -> None:
        b = field_element.to_bytes()  # 32 bytes LE
        self._digest.update(bytes([SCALAR]))
        self._digest.update(b)
        self._buf.extend(b)

    def push_point(self, point) -> None:
        b = point_to_bytes(point)  # 32 bytes compressed
        self._digest.update(bytes([POINT]))
        self._digest.update(b)
        self._buf.extend(b)

    def write_commitments(self, C_list: list, V_list: list) -> tuple:
        """Transcript C and V commitment lists and return them unchanged."""
        n_c = len(C_list)
        n_v = len(V_list)
        self._digest.update(n_c.to_bytes(8, "little"))
        for pt in C_list:
            self.push_point(pt)
        self._digest.update(n_v.to_bytes(8, "little"))
        for pt in V_list:
            self.push_point(pt)
        return C_list, V_list

    def challenge(self, field_cls):
        """Sample a challenge in field_cls.  

        Advance state with [CHALLENGE], then clone+finalize to get the 64-byte hash.
        Each call advances the running digest, so consecutive calls produce different values.
        """
        self._digest.update(bytes([CHALLENGE]))
        h = self._digest.copy().digest()  # 64 bytes
        res = field_cls.from_uniform_bytes(h)
        if res.is_zero():
            raise RuntimeError("zero challenge (negligible probability)")
        return res

    def challenge_bytes(self) -> bytes:
        self._digest.update(bytes([CHALLENGE]))
        return self._digest.copy().digest()

    def complete(self) -> bytes:
        return bytes(self._buf)


class VerifierTranscript:
    """Mirrors generalized_bulletproofs::transcript::VerifierTranscript."""

    def __init__(self, context: bytes, proof: bytes):
        if len(context) != 32:
            raise ValueError(f"transcript context must be 32 bytes, got {len(context)}")
        self._digest = hashlib.blake2b(digest_size=64)
        self._digest.update(context)
        self._proof = bytearray(proof)
        self._pos = 0

    def _read_bytes(self, n: int) -> bytes:
        chunk = bytes(self._proof[self._pos : self._pos + n])
        if len(chunk) < n:
            raise EOFError("not enough bytes in proof")
        self._pos += n
        return chunk

    def read_scalar(self, field_cls):
        self._digest.update(bytes([SCALAR]))
        raw = self._read_bytes(32)
        self._digest.update(raw)
        fe = field_cls.from_bytes(raw)
        if fe is None:
            raise ValueError("non-canonical scalar in proof")
        return fe

    def read_point(self, from_bytes_fn):
        self._digest.update(bytes([POINT]))
        raw = self._read_bytes(32)
        self._digest.update(raw)
        pt = from_bytes_fn(raw)
        if pt is None:
            raise ValueError("invalid point in proof")
        return pt

    def read_commitments(self, n_c: int, n_v: int, from_bytes_fn) -> tuple:
        self._digest.update(n_c.to_bytes(8, "little"))
        C = [self.read_point(from_bytes_fn) for _ in range(n_c)]
        self._digest.update(n_v.to_bytes(8, "little"))
        V = [self.read_point(from_bytes_fn) for _ in range(n_v)]
        return C, V

    def challenge(self, field_cls):
        self._digest.update(bytes([CHALLENGE]))
        h = self._digest.copy().digest()
        res = field_cls.from_uniform_bytes(h)
        if res.is_zero():
            raise RuntimeError("zero challenge (negligible probability)")
        return res

    def challenge_bytes(self) -> bytes:
        self._digest.update(bytes([CHALLENGE]))
        return self._digest.copy().digest()

    def is_exhausted(self) -> bool:
        """Return True if all proof bytes have been consumed."""
        return self._pos == len(self._proof)

    def complete(self) -> bytes:
        return bytes(self._proof[self._pos :])


class ScalarVector:
    """Thin list wrapper over field elements with Bulletproofs arithmetic."""

    __slots__ = ("v",)

    def __init__(self, elems):
        self.v = list(elems)

    # --- Construction helpers ---

    @classmethod
    def zeros(cls, n, field_cls=None, sample=None):
        """Return a zero vector of length n.

        Provide either field_cls (used as field_cls(0)) or sample
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

    def clone(self):
        return ScalarVector(list(self.v))

    # --- Arithmetic with a scalar (broadcast) ---

    def __add__(self, other):
        if isinstance(other, ScalarVector):
            if len(self.v) != len(other.v):
                raise ValueError(f"ScalarVector length mismatch: {len(self.v)} vs {len(other.v)}")
            return ScalarVector([a + b for a, b in zip(self.v, other.v)])
        return ScalarVector([a + other for a in self.v])

    def __sub__(self, other):
        if isinstance(other, ScalarVector):
            if len(self.v) != len(other.v):
                raise ValueError(f"ScalarVector length mismatch: {len(self.v)} vs {len(other.v)}")
            return ScalarVector([a - b for a, b in zip(self.v, other.v)])
        return ScalarVector([a - other for a in self.v])

    def __mul__(self, other):
        if isinstance(other, ScalarVector):
            if len(self.v) != len(other.v):
                raise ValueError(f"ScalarVector length mismatch: {len(self.v)} vs {len(other.v)}")
            return ScalarVector([a * b for a, b in zip(self.v, other.v)])
        return ScalarVector([a * other for a in self.v])

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __neg__(self):
        return ScalarVector([-a for a in self.v])

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

    # --- Split ---

    def split(self, at):
        return ScalarVector(self.v[:at]), ScalarVector(self.v[at:])

    def truncate(self, n):
        self.v = self.v[:n]
        return self


class PointVector:
    """Thin list wrapper over curve points with Bulletproofs arithmetic."""

    __slots__ = ("v",)

    def __init__(self, pts):
        self.v = list(pts)

    def __len__(self):
        return len(self.v)

    def __getitem__(self, i):
        return self.v[i]

    def clone(self):
        return PointVector(list(self.v))

    def split(self):
        """Split in half. Panics if not even."""
        if len(self.v) % 2 != 0:
            raise ValueError(f"PointVector length {len(self.v)} is not even, cannot split")
        mid = len(self.v) // 2
        return PointVector(self.v[:mid]), PointVector(self.v[mid:])


# ---------------------------------------------------------------------------
# Weight accumulation
# ---------------------------------------------------------------------------


def _accumulate_vector(acc_sv, sparse_weights, weight):
    """acc_sv += sparse_weights * weight.  Returns highest index written."""
    hi = 0
    for i, coeff in sparse_weights:
        acc_sv[i] = acc_sv[i] + coeff * weight
        hi = max(hi, i)
    return hi


# ---------------------------------------------------------------------------
# Pedersen commitments
# ---------------------------------------------------------------------------


class PedersenCommitment:
    """Opening of a Pedersen commitment: value * g + mask * h."""

    def __init__(self, value, mask):
        self.value = value
        self.mask = mask

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
# Generators / ProofGenerators / BatchVerifier
# ---------------------------------------------------------------------------


class ProofGenerators:
    """A slice of the full Generators set (reduced to a power of two)."""

    def __init__(self, g, h, g_bold, h_bold, identity):
        self._g = g
        self._h = h
        self._g_bold = list(g_bold)
        self._h_bold = list(h_bold)
        self.identity = identity  # the identity point of this curve

    def len(self):
        return len(self._g_bold)

    def g(self):
        return self._g

    def h(self):
        return self._h

    def g_bold(self, i):
        return self._g_bold[i]

    def h_bold(self, i):
        return self._h_bold[i]

    def g_bold_slice(self):
        return self._g_bold

    def h_bold_slice(self):
        return self._h_bold


class InsufficientGenerators(RuntimeError):
    """Not enough generators available for the circuit being proved or verified.
    """


class Generators:
    """Full generator set (g, h, g_bold, h_bold, h_sum).

    The circuit size grows with a transaction's input count, so how many
    generators a proof needs is not known until the transaction is in hand.
    Rather than fix a count up front, the set starts at whatever it was built
    with and grows on demand through `extend`, a callable (start, stop) ->
    (g_points, h_points) that decodes further generators from the parameter
    source. Without one the set is simply fixed at its initial size.
    """

    def __init__(self, g, h, g_bold, h_bold, identity, extend=None, capacity=None):
        if len(g_bold) != len(h_bold):
            raise ValueError(f"g_bold/h_bold length mismatch: {len(g_bold)} vs {len(h_bold)}")
        n = len(g_bold)
        if not (n > 0 and (n & (n - 1)) == 0):
            raise ValueError(f"g_bold length {n} must be a power of two and > 0")
        self._g = g
        self._h = h
        self._g_bold = list(g_bold)
        self._h_bold = list(h_bold)
        self.identity = identity
        self._extend = extend
        # How far `extend` can go. Without a loader the set cannot grow at all.
        self._capacity = n if (extend is None or capacity is None) else capacity

        self._h_sum = []
        self._h_running = identity
        self._h_seen = 0
        self._h_next = 1
        self._grow_h_sum(self._h_bold)

    def _grow_h_sum(self, new_points):
        """Continue the h_sum prefix sums over points appended to h_bold."""
        for h_pt in new_points:
            self._h_running = self._h_running + h_pt
            self._h_seen += 1
            if self._h_seen == self._h_next:
                self._h_sum.append(self._h_running)
                self._h_next *= 2

    def _ensure(self, n):
        """Make sure at least n generators are loaded, growing if needed."""
        have = len(self._g_bold)
        if n <= have:
            return
        if n > self._capacity:
            raise InsufficientGenerators(
                f"circuit needs {n} generators, only {self._capacity} available"
            )
        g_new, h_new = self._extend(have, n)
        if len(g_new) != n - have or len(h_new) != n - have:
            raise InsufficientGenerators(
                f"generator loader returned {len(g_new)}/{len(h_new)} points "
                f"for range [{have}, {n})"
            )
        self._g_bold.extend(g_new)
        self._h_bold.extend(h_new)
        self._grow_h_sum(h_new)

    def g(self):
        return self._g

    def h(self):
        return self._h

    def g_bold_slice(self):
        return self._g_bold

    def h_bold_slice(self):
        return self._h_bold

    @staticmethod
    def new_batch_verifier(field_cls):
        """Create an empty BatchVerifier over field_cls."""
        z = field_cls(0)
        return BatchVerifier(z, z, [], [], [], [], field_cls)

    def reduce(self, generators):
        """Return ProofGenerators sliced to generators (rounded up to power of 2).

        Raises InsufficientGenerators if the parameter source cannot supply that
        many. Never returns None, which would surface as an AttributeError deep
        inside the circuit rather than as a diagnosable failure.
        """
        if generators == 0:
            raise InsufficientGenerators("circuit asked for 0 generators")
        n = 1
        while n < generators:
            n *= 2
        self._ensure(n)
        return ProofGenerators(
            self._g,
            self._h,
            self._g_bold[:n],
            self._h_bold[:n],
            self.identity,
        )

    def verify(self, verifier):
        """Final batch verification: all scalar*point sums must equal identity."""
        # Silently dropping a claim past the end of a vector would let a proof
        # pass without that claim ever being checked, so refuse instead.
        for name, scalars, points in (
            ("g_bold", verifier.g_bold, self._g_bold),
            ("h_bold", verifier.h_bold, self._h_bold),
            ("h_sum", verifier.h_sum, self._h_sum),
        ):
            if len(scalars) > len(points):
                raise InsufficientGenerators(
                    f"batch verifier holds {len(scalars)} {name} claims but only "
                    f"{len(points)} generators are loaded"
                )
        pairs = [(verifier.g, self._g), (verifier.h, self._h)]
        pairs.extend(zip(verifier.g_bold, self._g_bold))
        pairs.extend(zip(verifier.h_bold, self._h_bold))
        pairs.extend(zip(verifier.h_sum, self._h_sum))
        pairs.extend(verifier.additional)
        result = multiexp(pairs, self.identity)
        return result.is_identity()


class BatchVerifier:
    """Accumulates scalar*point claims, verified in one multiexp."""

    def __init__(self, g_sc, h_sc, g_bold_scs, h_bold_scs, h_sum_scs, additional, field_cls):
        self.g = g_sc
        self.h = h_sc
        self.g_bold = list(g_bold_scs)
        self.h_bold = list(h_bold_scs)
        self.h_sum = list(h_sum_scs)
        self.additional = list(additional)  # [(scalar, point)]
        self.field_cls = field_cls

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
# Inner-Product Argument
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
        products[0] = challenges[0][1]  # x_inv
        products[1] = challenges[0][0]  # x

        for j in range(1, len(challenges)):
            x, x_inv = challenges[j]
            slots = (1 << (j + 1)) - 1
            while slots > 0:
                products[slots] = products[slots // 2] * x
                products[slots - 1] = products[slots // 2] * x_inv
                slots -= 2
    return products


class IpStatement:
    """Inner-product argument (Protocol 2 from Bulletproofs)."""

    def __init__(self, generators, h_bold_weights, u, P_point=None, verifier_weight=None):
        """
        generators     : ProofGenerators
        h_bold_weights : ScalarVector, per-h_bold scaling
        u              : field element, discrete log of the u-generator w.r.t. g
        P_point        : prover's P commitment (for prove mode)
        verifier_weight: random scalar (for verify mode)
        """
        self.generators = generators
        self.h_bold_weights = h_bold_weights
        self.u = u
        self.P_point = P_point
        self.verifier_weight = verifier_weight

    def prove(self, transcript, a, b, field_cls):
        """Run the IPA prover.

        transcript: ProverTranscript
        a, b      : ScalarVector witnesses
        field_cls : field class for challenge generation
        """
        gen = self.generators
        u_pt = gen.g() * self.u.v
        iden = gen.identity

        g_bold = PointVector(list(gen.g_bold_slice()))
        h_bold = PointVector(
            [gen.h_bold(i) * self.h_bold_weights[i].v for i in range(len(self.h_bold_weights.v))]
        )

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

            L_pairs = list(zip(a1.v, g_bold2.v)) + list(zip(b2.v, h_bold1.v)) + [(cl, u_pt)]
            R_pairs = list(zip(a2.v, g_bold1.v)) + list(zip(b1.v, h_bold2.v)) + [(cr, u_pt)]
            L = multiexp(L_pairs, iden)
            R = multiexp(R_pairs, iden)

            transcript.push_point(L)
            transcript.push_point(R)
            x = transcript.challenge(field_cls)
            x_inv = x.inv()

            g_bold = PointVector(
                [
                    multiexp([(x_inv, g1), (x, g2)], iden)
                    for g1, g2 in zip(g_bold1.v, g_bold2.v)
                ]
            )
            h_bold = PointVector(
                [
                    multiexp([(x, h1), (x_inv, h2)], iden)
                    for h1, h2 in zip(h_bold1.v, h_bold2.v)
                ]
            )

            # x is a public Fiat-Shamir challenge, so these do not need the
            # constant-time ladder that WPoint.__mul__ would use.
            P = multiexp([((x * x).v, L), (1, P), ((x_inv * x_inv).v, R)], iden)

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
        n = gen.len()

        verifier._ensure_g_bold(n)
        verifier._ensure_h_bold(n)

        lr_len = 0
        while (1 << lr_len) < n:
            lr_len += 1

        weight = self.verifier_weight

        L_pts = []
        R_pts = []
        xs = []
        for _ in range(lr_len):
            L_pts.append(transcript.read_point(point_from_bytes))
            R_pts.append(transcript.read_point(point_from_bytes))
            x = transcript.challenge(field_cls)
            xs.append(x)

        # batch inversion of all challenges
        x_invs = _batch_field_invert(xs)

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
            verifier.h_bold[i] = (
                verifier.h_bold[i]
                - weight * product_cache[len(product_cache) - 1 - i] * b * self.h_bold_weights[i]
            )

        verifier.g = verifier.g - weight * c * self.u


# ---------------------------------------------------------------------------
# Arithmetic Circuit Proof
# ---------------------------------------------------------------------------


class ArithmeticCircuitWitness:
    """Witness for an arithmetic circuit statement.

    aL, aR: ScalarVectors (left and right inputs)
    aO    : ScalarVector  (aL * aR element-wise, computed here)
    c     : list of PedersenVectorCommitment openings
    v     : list of PedersenCommitment openings
    """

    def __init__(self, aL, aR, c, v):
        if len(aL.v) != len(aR.v):
            raise ValueError(f"aL/aR length mismatch: {len(aL.v)} vs {len(aR.v)}")
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
        self.c = list(c)
        self.v = list(v)


# ---------------------------------------------------------------------------
# Folding the R1CS
# ---------------------------------------------------------------------------


def _fold_column(rows, kind, z, n, sample, ci=None):
    """Fold one wire-role column slice of the A matrix across all linear rows.

    A Generalized-Bulletproofs argument reduces the whole constraint system to a
    handful of vectors by taking a random linear combination of the rows: with a
    challenge z drawn after the commitments,

        weights[kind] = Sum_k  z^k * A_k[kind columns]

    for kind in {aL, aR, aO}, and once per commitment for the CG columns. A prover
    who satisfies the folded relation satisfies every row, except with negligible
    probability over z.

    Only the linear rows appear here: the multiplication rows aL_i * aR_i = aO_i
    are enforced structurally by the argument (aO is committed as the AO point and
    the relation falls out of the t-polynomial identity), never folded.

    Returns (weights, highest_index_written).
    """
    weights = ScalarVector.zeros(n, sample=sample)
    hi = 0
    for row, zk in zip(rows, z.v):
        columns = row.columns(kind)
        if ci is not None:
            if ci >= len(columns):
                continue
            columns = columns[ci]
        hi = max(hi, _accumulate_vector(weights, columns, zk))
    return weights, hi


class ArithmeticCircuitStatement:
    """GBP arithmetic circuit statement (prover and verifier)."""

    def __init__(self, generators, constraints, C_commitments, V_commitments):
        """
        generators    : ProofGenerators
        constraints   : list of r1cs.Lc, the linear rows' A-combinations
        C_commitments : list of points (vector commitment points)
        V_commitments : list of points (scalar commitment points)
        """
        self.generators = generators
        self.constraints = list(constraints)
        self.C = list(C_commitments)
        self.V = list(V_commitments)

    def n(self):
        return self.generators.len()

    def q(self):
        return len(self.constraints)

    def c(self):
        return len(self.C)

    def m(self):
        return len(self.V)

    # ---- yz challenge computation ----

    def _yz_challenges(self, y, z_1):
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
        gen = self.generators
        iden = gen.identity

        if len(witness.aL.v) > n:
            raise ValueError(f"witness aL length {len(witness.aL.v)} exceeds generator count {n}")

        alpha = rng_fn()
        beta = rng_fn()
        rho = rng_fn()

        # AI = sum(aL[i]*g_bold[i]) + sum(aR[i]*h_bold[i]) + alpha*h
        AI_pairs = (
            [(al, gen.g_bold(i)) for i, al in enumerate(witness.aL.v)]
            + [(ar, gen.h_bold(i)) for i, ar in enumerate(witness.aR.v)]
            + [(alpha, gen.h())]
        )
        AI = multiexp(AI_pairs, iden)

        # AO = sum(aO[i]*g_bold[i]) + beta*h
        AO_pairs = [(ao, gen.g_bold(i)) for i, ao in enumerate(witness.aO.v)] + [(beta, gen.h())]
        AO = multiexp(AO_pairs, iden)

        # S = sum(sL[i]*g_bold[i]) + sum(sR[i]*h_bold[i]) + rho*h
        sL = ScalarVector([rng_fn() for _ in range(n)])
        sR = ScalarVector([rng_fn() for _ in range(n)])
        S_pairs = (
            [(sl, gen.g_bold(i)) for i, sl in enumerate(sL.v)]
            + [(sr, gen.h_bold(i)) for i, sr in enumerate(sR.v)]
            + [(rho, gen.h())]
        )
        S = multiexp(S_pairs, iden)

        transcript.push_point(AI)
        transcript.push_point(AO)
        transcript.push_point(S)
        y = transcript.challenge(field_cls)
        z1 = transcript.challenge(field_cls)
        y_inv, z = self._yz_challenges(y, z1)
        y_pow = ScalarVector.powers(y, n)

        ni = 2 * c + 2  # n' = (2*c)+2, prove() and verify() must agree here
        ilr = ni // 2
        io = ni
        is_ = ni + 1
        jlr = ni // 2
        jo = 0
        js = ni + 1

        zero_sv = ScalarVector.zeros(n, sample=y)
        l = [zero_sv.clone() for _ in range(is_ + 1)]
        r = [zero_sv.clone() for _ in range(is_ + 1)]

        # Fold the R1CS: one z-weighted sum per wire-role column slice of A.
        rows = self.constraints
        l_weights, l_hi = _fold_column(rows, KIND_AL, z, n, y)
        r_weights, r_hi = _fold_column(rows, KIND_AR, z, n, y)
        o_weights, o_hi = _fold_column(rows, KIND_AO, z, n, y)
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
            cg_weights, cg_hi = _fold_column(rows, KIND_CG, z, n, y, ci=ci)
            cg_weights.truncate(cg_hi + 1)

            # Match verify(): l[g_values] at j = ni-1-ci, r[cg_weights] at i = 1+ci
            i = 1 + ci
            j = ni - i  # = ni - 1 - ci
            l[j] = ScalarVector(list(vc.g_values))
            r[i] = cg_weights

        # t polynomial: t[i+j] += l[i] · r[j]
        t_len = 1 + 2 * (len(l) - 1)
        t = ScalarVector.zeros(t_len, sample=y)
        for i, li in enumerate(l):
            for j, rj in enumerate(r):
                t[i + j] = t[i + j] + li.inner_product(iter(rj.v))

        # tau masks. The consensus prover commits T only for t-indices [ni//2 .. ni-1]
        # (T_before) and [ni+1 .. t_len-1] (T_after). The low coeffs t[0..ni//2-1] are zero
        # for this circuit, and index ni (t_caret) is revealed as a scalar.
        tau_before = [rng_fn() for _ in range(ni - ni // 2)]
        tau_after = [rng_fn() for _ in range(t_len - ni - 1)]

        for ti, tau in zip(t.v[ni // 2 : ni], tau_before):
            transcript.push_point(multiexp([(ti, gen.g()), (tau, gen.h())], iden))
        for ti, tau in zip(t.v[ni + 1 :], tau_after):
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
            _accumulate_vector(V_weights, constraint.columns(KIND_V), -zk)

        # tau_x = sum of tau_poly[i] * x^i
        v_masks_ip = V_weights.inner_product(v.mask for v in witness.v)
        if v_masks_ip is None:
            v_masks_ip = type(y)(0)
        # tau polynomial: zeros for the uncommitted low coeffs [0..ni//2-1], then
        # tau_before at [ni//2..ni-1], v_masks at [ni], tau_after at [ni+1..].
        tau_poly = ([type(y)(0)] * (ni // 2)) + tau_before + [v_masks_ip] + tau_after
        tau_x = type(y)(0)
        for i, coeff in enumerate(tau_poly):
            tau_x = tau_x + coeff * x_pow[i]

        # u = alpha*x[ilr] + beta*x[io] + rho*x[is] + sum(c.mask * x[i'])
        u = alpha * x_pow[ilr] + beta * x_pow[io] + rho * x_pow[is_]
        for ci, vc in enumerate(witness.c):
            j = ni - 1 - ci  # vc g_values live at l-index j (matches verify)
            u = u + x_pow[j] * vc.mask

        transcript.push_scalar(tau_x)
        transcript.push_scalar(u)
        transcript.push_scalar(t_caret)
        ip_x = transcript.challenge(field_cls)

        # P = sum(l[i]*g_bold[i]) + sum(y_inv[i]*r[i]*h_bold[i]) + ip_x*t_caret*g
        P_pairs = (
            [(l_eval[i], gen.g_bold(i)) for i in range(len(l_eval.v))]
            + [(y_inv[i] * r_eval[i], gen.h_bold(i)) for i in range(len(r_eval.v))]
            + [(ip_x * t_caret, gen.g())]
        )
        P_pt = multiexp(P_pairs, iden)

        IpStatement(gen, y_inv, ip_x, P_point=P_pt).prove(transcript, l_eval, r_eval, field_cls)

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

        ni = 2 * c + 2  # n' = (2*c)+2, must match prove()
        ilr = ni // 2
        io = ni
        is_ = ni + 1
        jlr = ni // 2

        l_r_len = 1 + ni + 1
        t_poly_len = 2 * l_r_len - 1

        verifier._ensure_g_bold(n)
        verifier._ensure_h_bold(n)

        def read_pt():
            return transcript.read_point(point_from_bytes)

        AI = read_pt()
        AO = read_pt()
        S = read_pt()
        y = transcript.challenge(field_cls)
        z1 = transcript.challenge(field_cls)
        y_inv, z = self._yz_challenges(y, z1)

        # The same fold the prover ran: rebuilt from the reconstructed rows.
        rows = self.constraints
        l_weights, _ = _fold_column(rows, KIND_AL, z, n, y)
        r_weights, _ = _fold_column(rows, KIND_AR, z, n, y)
        o_weights, _ = _fold_column(rows, KIND_AO, z, n, y)
        r_weights = r_weights * y_inv

        delta = r_weights.inner_product(iter(l_weights.v))

        # Only T[ni//2..ni-1] is written, the lower l-coefficients are zero
        T_before = [read_pt() for _ in range(ni - ni // 2)]
        T_after = [read_pt() for _ in range(t_poly_len - ni - 1)]
        x_pow = ScalarVector.powers(transcript.challenge(field_cls), t_poly_len)

        tau_x = transcript.read_scalar(field_cls)
        u = transcript.read_scalar(field_cls)
        t_caret = transcript.read_scalar(field_cls)

        # First verification equation: tau_x*h + t_caret*g == rhs
        w1 = rng_fn()
        verifier.g = verifier.g + t_caret * w1
        verifier.h = verifier.h + tau_x * w1

        V_weights = ScalarVector.zeros(len(self.V), sample=y)
        for constraint, zk in zip(self.constraints, z.v):
            _accumulate_vector(V_weights, constraint.columns(KIND_V), -zk)
        V_weights = V_weights * x_pow[ni]

        z_c_sum = z.inner_product(
            iter(
                constraint.c if constraint.c is not None else type(y)(0)
                for constraint in self.constraints
            )
        )
        if z_c_sum is None:
            z_c_sum = type(y)(0)  # empty constraints → zero
        verifier.g = verifier.g - w1 * x_pow[ni] * (delta - z_c_sum)

        for Vw, V_pt in zip(V_weights.v, self.V):
            verifier.additional.append((-w1 * Vw, V_pt))
        for i, T in enumerate(T_before):
            verifier.additional.append((-w1 * x_pow[ni // 2 + i], T))
        for i, T in enumerate(T_after):
            verifier.additional.append((-w1 * x_pow[ni + 1 + i], T))

        # Second block: P constraint
        w2 = rng_fn()
        xw = x_pow * w2

        verifier.additional.append((xw[ilr], AI))
        verifier.additional.append((xw[io], AO))
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
            cg, _ = _fold_column(rows, KIND_CG, z, n, y, ci=ci)

            # l[j=ni-1-ci] = g_values, r[i=1+ci] = cg_weights
            # Verifier: C gets x^j (l-side), h_bold gets WCG * x^i (r-side)
            i = 1 + ci
            j = ni - i
            C_pt = self.C[ci]
            WCG = cg
            verifier.additional.append((xw[j], C_pt))
            h_bold_scalars = h_bold_scalars + WCG * xw[i]

        h_bold_scalars = h_bold_scalars * y_inv
        for i, sc in enumerate(h_bold_scalars.v):
            verifier.h_bold[i] = verifier.h_bold[i] + sc

        verifier.h = verifier.h - w2 * u

        ip_x = transcript.challenge(field_cls)
        verifier.g = verifier.g + w2 * ip_x * t_caret

        IpStatement(gen, y_inv, ip_x, verifier_weight=w2).verify(
            verifier, transcript, field_cls, point_from_bytes
        )


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


def _batch_field_invert(elems):
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
