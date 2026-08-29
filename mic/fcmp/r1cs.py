"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

r1cs.py - the constraint system, as R1CS.

A Rank-1 Constraint System over a field F is a set of rows

    <A_k, z> * <B_k, z> = <C_k, z>

over one assignment vector z. Each of A_k, B_k, C_k is a linear combination (Lc) of the
entries of z, which is the only expression form R1CS has.

The wire vector is

    z = [ 1 | aL | aR | aO | CG | V ]

      1     the constant-one wire, ONE
      aL    left operands of the multiplication rows
      aR    right operands
      aO    their products
      CG    values inside the Pedersen vector commitments (the witness tape).
            CG(ci, j) is slot j of commitment ci
      V     values inside scalar Pedersen commitments (unused by FCMP++)

Two kinds of row exist:

  multiplication rows   {aL_i} * {aR_i} = {aO_i}. Generalized Bulletproofs
                        enforces these structurally: aO is committed as the AO
                        point and the relation falls out of the t-polynomial
                        identity. 
  linear rows           <A_k, z> * 1 = 0, i.e. B is the constant-one vector and C
                        is zero. These are what the argument folds, with a
                        challenge z: l_weights = sum_k z^k * A_k[aL], and likewise
                        for aR (see gbp.py).

Row order is part of the wire format. The proof engine folds the A-matrix columns
in row order, so emitting the same constraints in a different order produces a
different proof, which the chain rejects. R1CS therefore appends rows in the order
the gadgets create them, and Lc appends terms rather than summing them on insert.
"""

# ---------------------------------------------------------------------------
# Wire names: the entries of z
# ---------------------------------------------------------------------------

ONE = ("one",)

KIND_AL = "aL"
KIND_AR = "aR"
KIND_AO = "aO"
KIND_CG = "CG"
KIND_V = "V"


def aL(i: int) -> tuple:
    return (KIND_AL, i)


def aR(i: int) -> tuple:
    return (KIND_AR, i)


def aO(i: int) -> tuple:
    return (KIND_AO, i)


def CG(ci: int, j: int) -> tuple:
    return (KIND_CG, ci, j)


def V(i: int) -> tuple:
    return (KIND_V, i)


def as_wire(v) -> tuple:
    """Accept a wire tuple or a tape Variable, return a wire tuple."""
    if isinstance(v, tuple):
        return v
    return CG(v.commitment, v.index)  # tape.Variable(commitment, index)


def _max_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a > b else b


class Lc:
    """<w, z> + c, the only expression form in R1CS.

    Written with ordinary arithmetic, so a gadget reads as algebra::

        cs.assert_zero(y2 - x3 - curve.a * x - curve.b)

    Coefficients are kept bucketed per wire kind (WL for aL, WR for aR, WO
    for aO, WCG per commitment, WV), which is exactly the column slicing the
    fold in gbp.py needs, so folding stays O(nonzeros) and no re-bucketing
    happens on the proving path. 
    """

    __slots__ = ("WL", "WR", "WO", "WCG", "WV", "c",
                 "highest_a_index", "highest_c_index", "highest_v_index")

    def __init__(self):
        self.WL = []    # [(i, coeff)]: the A-row's aL columns
        self.WR = []
        self.WO = []
        self.WCG = []   # one list per commitment
        self.WV = []
        self.c = None   # the constant term, None until a term or constant is added
        self.highest_a_index = None
        self.highest_c_index = None
        self.highest_v_index = None

    # -- construction ------------------------------------------------------

    @classmethod
    def zero(cls) -> "Lc":
        return cls()

    @classmethod
    def constant(cls, k) -> "Lc":
        return cls().plus_constant(k)

    @classmethod
    def wire(cls, w, F: type) -> "Lc":
        return cls().term(F(1), w)

    def term(self, coeff, w) -> "Lc":
        """Append coeff · w. Mutates and returns self (builder style)."""
        w = as_wire(w)
        kind = w[0]
        if kind == KIND_AL:
            i = w[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WL.append((i, coeff))
        elif kind == KIND_AR:
            i = w[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WR.append((i, coeff))
        elif kind == KIND_AO:
            i = w[1]
            self.highest_a_index = _max_opt(self.highest_a_index, i)
            self.WO.append((i, coeff))
        elif kind == KIND_CG:
            ci, j = w[1], w[2]
            self.highest_c_index = _max_opt(self.highest_c_index, ci)
            self.highest_a_index = _max_opt(self.highest_a_index, j)
            while len(self.WCG) <= ci:
                self.WCG.append([])
            self.WCG[ci].append((j, coeff))
        elif kind == KIND_V:
            i = w[1]
            self.highest_v_index = _max_opt(self.highest_v_index, i)
            self.WV.append((i, coeff))
        else:
            raise ValueError(f"unknown wire kind {kind!r}")
        if self.c is None:
            self.c = coeff * type(coeff)(0)  # a zero of the right field type
        return self

    def plus_constant(self, k) -> "Lc":
        """Append the constant k. Mutates and returns self."""
        self.c = k if self.c is None else self.c + k
        return self

    # -- arithmetic --------------------------------------------------------

    def _absorb_shape(self, other):
        self.highest_a_index = _max_opt(self.highest_a_index, other.highest_a_index)
        self.highest_c_index = _max_opt(self.highest_c_index, other.highest_c_index)
        self.highest_v_index = _max_opt(self.highest_v_index, other.highest_v_index)

    def __add__(self, other):
        if not isinstance(other, Lc):
            return NotImplemented
        res = Lc()
        res._absorb_shape(self)
        res._absorb_shape(other)
        res.WL = self.WL + other.WL
        res.WR = self.WR + other.WR
        res.WO = self.WO + other.WO
        res.WCG = [
            (self.WCG[i] if i < len(self.WCG) else [])
            + (other.WCG[i] if i < len(other.WCG) else [])
            for i in range(max(len(self.WCG), len(other.WCG)))
        ]
        res.WV = self.WV + other.WV
        if self.c is None:
            res.c = other.c
        elif other.c is None:
            res.c = self.c
        else:
            res.c = self.c + other.c
        return res

    def __neg__(self):
        res = Lc()
        res._absorb_shape(self)
        res.WL = [(i, -w) for i, w in self.WL]
        res.WR = [(i, -w) for i, w in self.WR]
        res.WO = [(i, -w) for i, w in self.WO]
        res.WCG = [[(j, -w) for j, w in row] for row in self.WCG]
        res.WV = [(i, -w) for i, w in self.WV]
        res.c = -self.c if self.c is not None else None
        return res

    def __sub__(self, other):
        if not isinstance(other, Lc):
            return NotImplemented
        return self + (-other)

    def __mul__(self, scalar):
        """Scale by a field element. (R1CS has no Lc*Lc. That needs a mul row.)"""
        res = Lc()
        res._absorb_shape(self)
        res.WL = [(i, w * scalar) for i, w in self.WL]
        res.WR = [(i, w * scalar) for i, w in self.WR]
        res.WO = [(i, w * scalar) for i, w in self.WO]
        res.WCG = [[(j, w * scalar) for j, w in row] for row in self.WCG]
        res.WV = [(i, w * scalar) for i, w in self.WV]
        res.c = self.c * scalar if self.c is not None else None
        return res

    __rmul__ = __mul__

    # -- inspection --------------------------------------------------------

    def columns(self, kind: str):
        """The A-row's column slice for one wire kind: [(index, coeff), …].
        """
        if kind == KIND_AL:
            return self.WL
        if kind == KIND_AR:
            return self.WR
        if kind == KIND_AO:
            return self.WO
        if kind == KIND_CG:
            return self.WCG
        if kind == KIND_V:
            return self.WV
        raise ValueError(f"unknown wire kind {kind!r}")

    def named_terms(self, F: type) -> dict:
        """{wire_tuple: coeff} with duplicates summed, the constant on ONE.
        """
        out = {}

        def acc(name, w):
            out[name] = out.get(name, F(0)) + w

        for i, w in self.WL:
            acc(aL(i), w)
        for i, w in self.WR:
            acc(aR(i), w)
        for i, w in self.WO:
            acc(aO(i), w)
        for ci, row in enumerate(self.WCG):
            for j, w in row:
                acc(CG(ci, j), w)
        for i, w in self.WV:
            acc(V(i), w)
        if self.c is not None:
            acc(ONE, self.c)
        return out

    def evaluate(self, read_wire, F: type):
        """Evaluate against an assignment. read_wire(wire_tuple) -> F | None.
        """
        zero = F(0)
        res = self.c if self.c is not None else zero

        def val(w):
            v = read_wire(w)
            return zero if v is None else v

        for i, w in self.WL:
            res = res + w * val(aL(i))
        for i, w in self.WR:
            res = res + w * val(aR(i))
        for i, w in self.WO:
            res = res + w * val(aO(i))
        for ci, row in enumerate(self.WCG):
            for j, w in row:
                res = res + w * val(CG(ci, j))
        for i, w in self.WV:
            res = res + w * val(V(i))
        return res


# ---------------------------------------------------------------------------
# Rows and blocks
# ---------------------------------------------------------------------------


class Row:
    """One R1CS row: ⟨A, z⟩ · ⟨B, z⟩ = ⟨C, z⟩."""

    __slots__ = ("A", "B", "C", "kind")

    def __init__(self, A, B, C, kind):
        self.A, self.B, self.C = A, B, C
        self.kind = kind  # "mul" | "linear"

    def __repr__(self):
        return f"<R1CS {self.kind} row>"


class Block:
    """The rows one gadget invocation contributed.
    """

    __slots__ = ("name", "depth", "start", "end", "introduced")

    def __init__(self, name, depth, start):
        self.name = name
        self.depth = depth
        self.start = start        # index of the first row, into R1CS.rows()
        self.end = start          # exclusive, set when the block closes
        self.introduced = set()   # wires this gadget's mul rows created

    def n_rows(self) -> int:
        return self.end - self.start


# ---------------------------------------------------------------------------
# R1CS: the constraint system builder
# ---------------------------------------------------------------------------


class Witness:
    """The prover's assignment to the wires it owns.

    aL/aR are filled one entry per multiplication row (aO is their product and
    is never stored). Commitments are the Pedersen vector commitments whose slots
    the CG wires read. Scalars are the (unused by FCMP++) V commitments.
    """

    def __init__(self, commitments=None, scalars=None):
        self.aL = []
        self.aR = []
        self.commitments = list(commitments or [])
        self.scalars = list(scalars or [])


class R1CS:
    """Build a constraint system by writing R1CS rows.

    Prover mode carries a Witness and every row can be evaluated. Verifier mode
    carries none, eval returns None, and the gadgets emit exactly the same rows
    from public data alone. That symmetry is the whole point: the verifier
    reconstructs this system from scratch and checks the proof against it.
    """

    def __init__(self, field_cls: type, witness=None):
        self.F = field_cls
        self.witness = witness
        self.n_mul = 0            # number of multiplication rows
        self.constraints = []     # the linear rows' A-combinations, in order
        self._rows = []
        self.blocks = []
        self._block_stack = []
        self._root_block = None

    # -- expression helpers ------------------------------------------------

    def one(self) -> "Lc":
        return Lc.constant(self.F(1))

    def constant(self, k) -> "Lc":
        return Lc.constant(k if hasattr(k, "v") else self.F(k))

    def wire(self, w) -> "Lc":
        return Lc.wire(w, self.F)

    def zero(self) -> "Lc":
        return Lc.zero()

    # -- rows --------------------------------------------------------------

    def mul(self, a: "Lc", b: "Lc", witness=None) -> "Lc":
        """Row ⟨a, z⟩ · ⟨b, z⟩ = ⟨out, z⟩. Returns out, a fresh product wire.

        Lowering: allocate multiplication row i, pin aL_i = a and aR_i = b with
        one linear row each, and return aO_i. In prover mode the operand values
        are read off the current assignment unless witness=(a_val, b_val) is
        given.

        The pinning rows are emitted unconditionally, even when the operand is
        already that very wire. The redundant row is part of the wire format, and
        dropping it would change the proof.
        """
        return self.wire(self._mul_row(a, b, witness)[2])

    def mul_free_left(self, b: "Lc", witness) -> tuple:
        """A multiplication row whose left operand is a fresh witness value.

        Used where the left factor is a secret with no defining linear form, e.g. the
        slope λ of an incomplete addition, for instance. No pinning row is emitted
        for it, so it enters the system as an unconstrained wire that the gadget's
        own rows must then pin. Returns (left, out).
        """
        left, _right, out = self._mul_row(None, b, (witness, None))
        return self.wire(left), self.wire(out)

    def mul_free_right(self, a: "Lc", witness) -> tuple:
        """A multiplication row whose right operand is a fresh witness value.

        Used where the right factor is a value only the prover can supply, e.g. an
        inverse, for instance. Returns (right, out).
        """
        _left, right, out = self._mul_row(a, None, (None, witness))
        return self.wire(right), self.wire(out)

    def new_wires(self, witness=None) -> tuple:
        """Introduce two fresh wires, initially unconstrained. Returns their names.

        A multiplication row is the only way to bring new wires into the system, so
        allocating one with both operands free and discarding the product is how
        a caller obtains raw wires to constrain later. The cross-curve layers do
        this for a node hash's coordinates, which the layer's own rows then pin.

        witness is the pair of values in prover mode, None when verifying.
        Cost: 1 mul, 0 linear.
        """
        left, right, _out = self._mul_row(None, None, witness)
        return left, right

    def assert_zero(self, lc: "Lc") -> None:
        """Row ⟨lc, z⟩ · 1 = 0."""
        self.constraints.append(lc)
        self._append_row(Row(lc, self.one(), Lc.zero(), "linear"))

    def assert_eq(self, x: "Lc", y: "Lc") -> None:
        """Row ⟨x − y, z⟩ · 1 = 0."""
        self.assert_zero(x - y)

    def _mul_row(self, a, b, witness):
        """Allocate multiplication row i and pin whichever operands are given.

        Row order is wire format: the multiplication row first, then the aL pin,
        then the aR pin, then whatever the gadget adds. Do not reorder.
        """
        i = self.n_mul
        left, right, out = aL(i), aR(i), aO(i)
        self.n_mul += 1

        va, vb = witness if witness is not None else (None, None)
        if self.witness is not None:
            # An operand with a defining linear form is read off the assignment.
            # A free operand must have been handed its value by the gadget.
            if va is None:
                assert a is not None, "prover: a free left operand needs a witness value"
                va = self.eval(a)
            if vb is None:
                assert b is not None, "prover: a free right operand needs a witness value"
                vb = self.eval(b)
            self.witness.aL.append(va)
            self.witness.aR.append(vb)
        else:
            assert va is None and vb is None, "verifier must not supply witness values"

        blk = self._current_block()
        self._append_row(Row(self.wire(left), self.wire(right), self.wire(out), "mul"))
        blk.introduced.update({left, right, out})

        if a is not None:
            self.assert_zero(a - self.wire(left))
        if b is not None:
            self.assert_zero(b - self.wire(right))
        return left, right, out

    def _append_row(self, row):
        self._rows.append(row)
        self._current_block().end = len(self._rows)

    # -- witness -----------------------------------------------------------

    def eval(self, lc):
        """Value of lc under the current assignment, None when verifying."""
        if self.witness is None:
            return None
        return lc.evaluate(self.read_wire, self.F)

    def read_wire(self, w):
        """The assignment's value for one wire, or None if it has none."""
        if self.witness is None:
            return None
        kind = w[0]
        wit = self.witness
        if kind == KIND_AL:
            return wit.aL[w[1]] if w[1] < len(wit.aL) else None
        if kind == KIND_AR:
            return wit.aR[w[1]] if w[1] < len(wit.aR) else None
        if kind == KIND_AO:
            i = w[1]
            if i < len(wit.aL):
                return wit.aL[i] * wit.aR[i]
            return None
        if kind == KIND_CG:
            ci, j = w[1], w[2]
            if ci < len(wit.commitments):
                gv = wit.commitments[ci].g_values
                if j < len(gv):
                    return gv[j]
            return None
        if kind == KIND_V:
            i = w[1]
            return wit.scalars[i].value if i < len(wit.scalars) else None
        return None

    # -- blocks ------------------------------------------------------------

    def record_block(self, name):
        """Attribute every row emitted inside this scope to gadget name."""
        return _BlockScope(self, name)

    def _current_block(self):
        if self._block_stack:
            return self._block_stack[-1]
        if self._root_block is None:
            self._root_block = Block("<root>", 0, len(self._rows))
            self.blocks.append(self._root_block)
        return self._root_block

    # -- inspection --------------------------------------------------------

    def rows(self):
        """Every R1CS row, multiplication rows included, in emission order."""
        return list(self._rows)

    def linear_rows(self):
        """Only the rows the proof engine folds (⟨A, z⟩ · 1 = 0)."""
        return list(self.constraints)

    def describe(self):
        return (f"R1CS over {self.F.__name__}: {len(self._rows)} rows "
                f"({self.n_mul} multiplication, {len(self.constraints)} linear), "
                f"{len(self.blocks)} gadget blocks")


class _BlockScope:
    def __init__(self, cs, name):
        self.cs = cs
        self.name = name
        self.block = None

    def __enter__(self):
        self.block = Block(self.name, len(self.cs._block_stack), len(self.cs._rows))
        self.cs.blocks.append(self.block)
        self.cs._block_stack.append(self.block)
        return self.block

    def __exit__(self, *exc):
        self.block.end = len(self.cs._rows)
        self.cs._block_stack.pop()
        return False


# ---------------------------------------------------------------------------
# Matrix view: z layout, densification, extraction
# ---------------------------------------------------------------------------


def build_layout(cs):
    """Assign z columns: z = [1] + aL + aR + aO + CG + V.

    Returns (col_of, col_names). The committed (CG/V) width is known exactly in
    prover mode. When verifying we take a column for every index any row mentions.
    """
    M = cs.n_mul
    col_of = {ONE: 0}
    col_names = [ONE]

    def add(name):
        col_of[name] = len(col_names)
        col_names.append(name)

    for i in range(M):
        add(aL(i))
    for i in range(M):
        add(aR(i))
    for i in range(M):
        add(aO(i))

    wit = cs.witness
    if wit is not None:
        for ci, commitment in enumerate(wit.commitments):
            for j in range(len(commitment.g_values)):
                add(CG(ci, j))
        for i in range(len(wit.scalars)):
            add(V(i))
    else:
        max_cg, max_v = {}, -1
        for lc in cs.constraints:
            for ci, row in enumerate(lc.WCG):
                for j, _w in row:
                    max_cg[ci] = max(max_cg.get(ci, -1), j)
            for i, _w in lc.WV:
                max_v = max(max_v, i)
        for ci in sorted(max_cg):
            for j in range(max_cg[ci] + 1):
                add(CG(ci, j))
        for i in range(max_v + 1):
            add(V(i))

    return col_of, col_names


def witness_vector(cs, col_of, ncols):
    """The satisfying assignment z, from a prover-mode system."""
    F = cs.F
    assert cs.witness is not None, "z needs a prover-mode system"
    z = [F(0)] * ncols
    z[0] = F(1)
    for i, (l, r) in enumerate(zip(cs.witness.aL, cs.witness.aR)):
        z[col_of[aL(i)]] = l
        z[col_of[aR(i)]] = r
        z[col_of[aO(i)]] = l * r
    for ci, commitment in enumerate(cs.witness.commitments):
        for j, val in enumerate(commitment.g_values):
            z[col_of[CG(ci, j)]] = val
    for i, v in enumerate(cs.witness.scalars):
        z[col_of[V(i)]] = v.value
    return z


def to_sparse(cs):
    """The whole system as column-indexed sparse rows.

    Returns (sparse, z, col_of, col_names) where each sparse entry is a triple of
    {col_index: coeff} dicts. z is None when verifying.
    """
    F = cs.F
    col_of, col_names = build_layout(cs)

    def cols(lc):
        return {col_of[name]: w for name, w in lc.named_terms(F).items()}

    sparse = [(cols(r.A), cols(r.B), cols(r.C)) for r in cs._rows]
    z = witness_vector(cs, col_of, len(col_names)) if cs.witness is not None else None
    return sparse, z, col_of, col_names
