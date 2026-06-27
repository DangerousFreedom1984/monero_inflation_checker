"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

fcmp.py — Full FCMP++ prove() and supporting structures.

Translates:
  crypto/fcmps/src/lib.rs            (Fcmp::prove, Fcmp::transcript, ipa_rows, Self::input)
  crypto/fcmps/src/prover/mod.rs     (BranchesWithBlinds, transcript_branches,
                                      transcript_inputs, transcript_blinds)
  crypto/fcmps/src/prover/blinds.rs  (ScalarMulAndDivisor, PreparedBlind, OBlind, IBlind,
                                      IBlindBlind, CBlind, OutputBlinds, BranchBlind)
  crypto/fcmps/src/params.rs         (FcmpParams)
"""

import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from field import HeliosField, SeleneField
from curve import WPoint, point_to_bytes
from transcript import ProverTranscript
from tape import VectorCommitmentTape, COMMITMENT_WORD_LEN
from circuit import (
    Circuit,
    DlogParams,
    CurveSpec,
    GeneratorTable,
    OC_PARAMS,
    C1_PARAMS,
    C2_PARAMS,
    PointWithDlog,
    Divisor,
)
from divisors import ScalarDecomposition
from polynomial import Poly
from multiexp import multiexp as _multiexp
from gbp import PedersenVectorCommitment, ScalarVector, ArithmeticCircuitWitness

# ---------------------------------------------------------------------------
# Constants  (lib.rs lines 57-67)
# ---------------------------------------------------------------------------

LAYER_ONE_LEN = 38
LAYER_TWO_LEN = 18

_C1_LEAVES_ROWS = 97
_C1_BRANCH_ROWS = 52
_C2_ROWS_PER_LAYER = 32
_C1_TARGET = 256
_C2_TARGET = 128


# ---------------------------------------------------------------------------
# Helper: next power of two
# ---------------------------------------------------------------------------


def _next_pow2(n: int) -> int:
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


# ---------------------------------------------------------------------------
# Helper: convert Poly from divisors.py to the dict expected by tape.py
# ---------------------------------------------------------------------------


def _poly_to_tape_dict(poly: Poly):
    """Convert a Poly object to the dict format consumed by tape.append_divisor()."""
    y_val = poly.y[0] if poly.y else None
    yx_list = list(poly.yx[0]) if poly.yx else []
    x_list = list(poly.x)  # x[0] = 1 (normalized); tape skips x[0]
    return {
        "y": y_val,
        "yx": yx_list,
        "x": x_list,
        "zero": poly.zero,
    }


# ===========================================================================
# Scalar-mul-and-divisor  (blinds.rs: ScalarMulAndDivisor)
# ===========================================================================


class ScalarMulAndDivisor:
    """Precomputed scalar * generator, its coordinates, and the divisor polynomial.

    For OC curve: generator is a Wei25519Point, coordinates are HeliosField.
    For C1 curve: generator is WPoint(Selene), coordinates are SeleneField.
    For C2 curve: generator is WPoint(Helios), coordinates are HeliosField.
    """

    def __init__(self, point, x, y, divisor: Poly):
        self.point = point  # curve point (Wei25519Point or WPoint)
        self.x = x  # field element (x-coordinate)
        self.y = y  # field element (y-coordinate)
        self.divisor = divisor  # Poly with x[0]=1 (normalize_x_coefficient already applied)

    @classmethod
    def new_oc(cls, A_wei, scalar_decomp: ScalarDecomposition):
        """Build for OC (Wei25519).

        A_wei       : Wei25519Point — the generator
        scalar_decomp: ScalarDecomposition over Ed25519 scalars
        """
        from divisors import Wei25519Point

        p = A_wei * scalar_decomp.scalar
        px, py = p.to_affine()
        divisor = scalar_decomp.scalar_mul_divisor(A_wei)
        return cls(p, HeliosField(px), HeliosField(py), divisor)

    @classmethod
    def new_c1(cls, A: WPoint, scalar_decomp: ScalarDecomposition):
        """Build for C1 (Selene).

        A           : WPoint on Selene
        scalar_decomp: ScalarDecomposition (must be over the C1 scalar field = HeliosField)
        """
        p = A * scalar_decomp.scalar
        divisor = scalar_decomp.scalar_mul_divisor_selene(A)
        return cls(p, SeleneField(p.x.v), SeleneField(p.y.v), divisor)

    @classmethod
    def new_c2(cls, A: WPoint, scalar_decomp: ScalarDecomposition):
        """Build for C2 (Helios).

        A           : WPoint on Helios
        scalar_decomp: ScalarDecomposition (must be over the C2 scalar field = SeleneField)
        """
        p = A * scalar_decomp.scalar
        divisor = scalar_decomp.scalar_mul_divisor_helios(A)
        return cls(p, HeliosField(p.x.v), HeliosField(p.y.v), divisor)


# ---------------------------------------------------------------------------
# PreparedBlind  (blinds.rs: PreparedBlind)
# ---------------------------------------------------------------------------


class PreparedBlind:
    """A blind scalar + its scalar-mul-and-divisor result."""

    def __init__(self, scalar: ScalarDecomposition, scalar_mul_and_divisor: ScalarMulAndDivisor):
        self.scalar = scalar
        self.scalar_mul_and_divisor = scalar_mul_and_divisor


# ---------------------------------------------------------------------------
# Typed blind wrappers  (blinds.rs)
# ---------------------------------------------------------------------------


class OBlind:
    """Blind for O (output key). Uses OC generator T."""

    def __init__(self, prepared: PreparedBlind):
        self._p = prepared

    @classmethod
    def new(cls, T_wei, scalar_decomp):
        return cls(PreparedBlind(scalar_decomp, ScalarMulAndDivisor.new_oc(T_wei, scalar_decomp)))

    @property
    def inner(self):
        return self._p


class IBlind:
    """Blind for I (key-image generator). Two divisors for generators U and V, one scalar."""

    def __init__(self, scalar: ScalarDecomposition, u: ScalarMulAndDivisor, v: ScalarMulAndDivisor):
        self.scalar = scalar
        self.u = u
        self.v = v

    @classmethod
    def new(cls, U_wei, V_wei, scalar_decomp: ScalarDecomposition):
        u = ScalarMulAndDivisor.new_oc(U_wei, scalar_decomp)
        v = ScalarMulAndDivisor.new_oc(V_wei, scalar_decomp)
        return cls(scalar_decomp, u, v)


class IBlindBlind:
    """Blind for the blind of I. Uses OC generator V as the scalar-mul base."""

    def __init__(self, prepared: PreparedBlind):
        self._p = prepared

    @classmethod
    def new(cls, T_wei, scalar_decomp):
        return cls(PreparedBlind(scalar_decomp, ScalarMulAndDivisor.new_oc(T_wei, scalar_decomp)))

    @property
    def inner(self):
        return self._p


class CBlind:
    """Blind for C (commitment). Uses OC generator G."""

    def __init__(self, prepared: PreparedBlind):
        self._p = prepared

    @classmethod
    def new(cls, G_wei, scalar_decomp):
        return cls(PreparedBlind(scalar_decomp, ScalarMulAndDivisor.new_oc(G_wei, scalar_decomp)))

    @property
    def inner(self):
        return self._p


# ---------------------------------------------------------------------------
# OutputBlinds  (blinds.rs: OutputBlinds)
# ---------------------------------------------------------------------------


class OutputBlinds:
    """Collection of all blinds for one output."""

    def __init__(
        self, o_blind: OBlind, i_blind: IBlind, i_blind_blind: IBlindBlind, c_blind: CBlind
    ):
        self.o_blind = o_blind
        self.i_blind = i_blind
        self.i_blind_blind = i_blind_blind
        self.c_blind = c_blind

    def blind(self, output_O_affine, output_I_affine, output_C_affine):
        """Compute the blinded input tuple (O_tilde, I_tilde, R, C_tilde).

        output_*_affine: (x, y) field-element tuples for points O, I, C on OC.
        Returns dict with keys 'O_tilde', 'I_tilde', 'R', 'C_tilde', each as (x, y) tuples.
        """

        # Helper: subtract Wei25519 affine points using group law
        # We work in HeliosField integers
        def sub_oc(px, py, qx, qy):
            """(px, py) - (qx, qy) = (px, py) + (qx, -qy) on Wei25519."""
            return _oc_add(int(px), int(py), int(qx), -int(qy) % HeliosField.P)

        Ox, Oy = int(output_O_affine[0]), int(output_O_affine[1])
        Ix, Iy = int(output_I_affine[0]), int(output_I_affine[1])
        Cx, Cy = int(output_C_affine[0]), int(output_C_affine[1])

        o_bx = int(self.o_blind.inner.scalar_mul_and_divisor.x)
        o_by = int(self.o_blind.inner.scalar_mul_and_divisor.y)
        i_ux = int(self.i_blind.u.x)
        i_uy = int(self.i_blind.u.y)
        i_vx = int(self.i_blind.v.x)
        i_vy = int(self.i_blind.v.y)
        ib_x = int(self.i_blind_blind.inner.scalar_mul_and_divisor.x)
        ib_y = int(self.i_blind_blind.inner.scalar_mul_and_divisor.y)
        c_bx = int(self.c_blind.inner.scalar_mul_and_divisor.x)
        c_by = int(self.c_blind.inner.scalar_mul_and_divisor.y)

        P = HeliosField.P
        O_tilde = sub_oc(Ox, Oy, o_bx, o_by)  # O − o_blind
        I_tilde = sub_oc(Ix, Iy, i_ux, i_uy)  # I − i_blind_u
        R = sub_oc(ib_x, ib_y, i_vx, i_vy)  # blind_blind − i_blind_v
        C_tilde = sub_oc(Cx, Cy, c_bx, c_by)  # C − c_blind

        def to_f(rx, ry):
            return (HeliosField(rx), HeliosField(ry))

        return {
            "O_tilde": to_f(*O_tilde),
            "I_tilde": to_f(*I_tilde),
            "R": to_f(*R),
            "C_tilde": to_f(*C_tilde),
        }


def _oc_add(x1, y1, x2, y2):
    """Affine addition on Wei25519 (OC curve base field HeliosField)."""
    from divisors import WEI25519_A

    P = HeliosField.P
    if x1 == x2 and y1 == y2:
        # Doubling
        m = (3 * x1 * x1 + WEI25519_A) * pow(2 * y1, P - 2, P) % P
    else:
        # Addition
        m = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


# ---------------------------------------------------------------------------
# BranchBlind  (blinds.rs: BranchBlind)
# ---------------------------------------------------------------------------


class BranchBlind:
    """Blind for a branch node (on C1 or C2)."""

    def __init__(self, prepared: PreparedBlind):
        self._p = prepared

    @property
    def inner(self):
        return self._p


# ===========================================================================
# Input / Output structures
# ===========================================================================


class Output:
    """An output tuple (O, I, C) on the OC curve — affine (x, y) as HeliosField pairs."""

    def __init__(self, O: tuple, I: tuple, C: tuple):
        self.O = O  # (HeliosField, HeliosField)
        self.I = I
        self.C = C


class PerInputData:
    """One input's output + blinds + branch path."""

    def __init__(
        self,
        output: Output,
        output_blinds: OutputBlinds,
        branches_c1: list,
        branches_c2: list,
        leaves=None,
    ):
        self.output = output
        self.output_blinds = output_blinds
        self.branches_c1 = branches_c1  # list of lists of SeleneField (Selene field)
        self.branches_c2 = branches_c2  # list of lists of HeliosField (Helios field)
        self.leaves = leaves  # list of SeleneField (6*LAYER_ONE_LEN elements)


# ---------------------------------------------------------------------------
# Root branch options  (prover/mod.rs: RootBranch)
# ---------------------------------------------------------------------------


class RootBranchLeaves:
    def __init__(self, outputs):
        self.outputs = outputs  # list of Output


class RootBranchC1:
    def __init__(self, branch: list):
        self.branch = branch  # list of SeleneField


class RootBranchC2:
    def __init__(self, branch: list):
        self.branch = branch  # list of HeliosField


# ---------------------------------------------------------------------------
# BranchesWithBlinds  (prover/mod.rs)
# ---------------------------------------------------------------------------


class BranchesWithBlinds:
    """All prover inputs for a single prove() call.

    per_input       : list of PerInputData (one per proved output)
    root            : RootBranchLeaves | RootBranchC1 | RootBranchC2
    branches_1_blinds: list of BranchBlind (for C1 Selene branches)
    branches_2_blinds: list of BranchBlind (for C2 Helios branches)
    """

    def __init__(self, per_input, root, branches_1_blinds, branches_2_blinds):
        self.per_input = per_input
        self.root = root
        self.branches_1_blinds = branches_1_blinds
        self.branches_2_blinds = branches_2_blinds


# ===========================================================================
# FcmpParams  (params.rs)
# ===========================================================================


class FcmpParams:
    """Protocol parameters: generators, hash init points, generator tables.

    C1 = Selene (base field SeleneField, scalar field HeliosField)
    C2 = Helios (base field HeliosField, scalar field SeleneField)
    OC = Ed25519/Wei25519 (base field HeliosField)
    """

    def __init__(
        self,
        curve_1_generators,  # Generators object for C1 (Selene)
        curve_2_generators,  # Generators object for C2 (Helios)
        curve_1_hash_init: WPoint,  # Selene point
        curve_2_hash_init: WPoint,  # Helios point
        G_table: GeneratorTable,  # OC generator G table (OC_PARAMS)
        T_table: GeneratorTable,  # OC generator T table (OC_PARAMS)
        U_table: GeneratorTable,  # OC generator U table (OC_PARAMS)
        V_table: GeneratorTable,  # OC generator V table (OC_PARAMS)
        H_1_table: GeneratorTable,  # C2 field, C1Parameters
        H_2_table: GeneratorTable,  # C1 field, C2Parameters
    ):
        self.curve_1_generators = curve_1_generators
        self.curve_2_generators = curve_2_generators
        self.curve_1_hash_init = curve_1_hash_init
        self.curve_2_hash_init = curve_2_hash_init
        self.G_table = G_table
        self.T_table = T_table
        self.U_table = U_table
        self.V_table = V_table
        self.H_1_table = H_1_table  # used in c2_circuit.additional_layer_discrete_log_challenge
        self.H_2_table = H_2_table  # used in c1_circuit.additional_layer_discrete_log_challenge


# ===========================================================================
# Fcmp — the main prove/verify structure
# ===========================================================================


class Fcmp:
    """Full-chain membership proof."""

    def __init__(self, proof: bytes, root_blind_pok: bytes):
        assert len(root_blind_pok) == 64
        self.proof = proof
        self.root_blind_pok = root_blind_pok

    # -----------------------------------------------------------------------
    # ipa_rows  (lib.rs lines 245-264)
    # -----------------------------------------------------------------------

    @staticmethod
    def ipa_rows(inputs: int, layers: int) -> tuple:
        """Compute (c1_padded, c2_padded) for IPA round counts."""
        non_leaves_c1 = max(layers - 1, 0) // 2
        c1_rows = inputs * (_C1_LEAVES_ROWS + non_leaves_c1 * _C1_BRANCH_ROWS)
        c2_rows = inputs * max(layers // 2 * _C2_ROWS_PER_LAYER, 1)
        c1_rows = max(_next_pow2(c1_rows), _C1_TARGET)
        c2_rows = max(_next_pow2(c2_rows), _C2_TARGET)
        return (c1_rows, c2_rows)

    # -----------------------------------------------------------------------
    # transcript  (lib.rs lines 345-381)
    # -----------------------------------------------------------------------

    @staticmethod
    def transcript(
        tree_root_is_c1: bool, tree_root_bytes: bytes, inputs: list, root_blind_R: bytes
    ) -> bytes:
        """Compute the 32-byte FCMP context hash."""
        h = hashlib.blake2b(digest_size=32)
        # Tree root
        h.update(bytes([0 if tree_root_is_c1 else 1]))
        h.update(tree_root_bytes)
        # Input tuples
        h.update(len(inputs).to_bytes(4, "little"))  # u32 LE (not u64)
        for inp in inputs:
            for f in [
                inp["O_tilde"][0],
                inp["O_tilde"][1],
                inp["I_tilde"][0],
                inp["I_tilde"][1],
                inp["R"][0],
                inp["R"][1],
                inp["C_tilde"][0],
                inp["C_tilde"][1],
            ]:
                h.update(f.to_bytes())
        # Root blind nonce
        h.update(root_blind_R)
        return h.digest()

    # -----------------------------------------------------------------------
    # _transcript_branches  (prover/mod.rs lines 337-388)
    # -----------------------------------------------------------------------

    @staticmethod
    def _transcript_branches(
        branches: BranchesWithBlinds, c1_tape: VectorCommitmentTape, c2_tape: VectorCommitmentTape
    ):
        """Fill branch data into c1_tape and c2_tape.

        Mirrors transcript_branches() exactly:
          - For each input: optional leaf branch → c1_layers → c2_layers
          - Then the root branch (separate)

        For 1-layer trees: leaves=None per-input; root=RootBranchLeaves.

        Returns (per_input_vars, root_vars) where per_input_vars is a list of
        (c1_vars_list, c2_vars_list) per input.
        """

        def flatten_leaves(outputs):
            """Flatten list of Output to HeliosField scalars, padded to 6*LAYER_ONE_LEN."""
            scalars = []
            for out in outputs:
                scalars.extend([out.O[0], out.O[1], out.I[0], out.I[1], out.C[0], out.C[1]])
            while len(scalars) < 6 * LAYER_ONE_LEN:
                scalars.append(HeliosField(0))
            return scalars

        per_input_vars = []
        for data in branches.per_input:
            c1_vars = []
            c2_vars = []

            # Leaf branch (None if root is leaves, i.e. 1-layer tree)
            if data.leaves is not None:
                flat = flatten_leaves(data.leaves)
                c1_vars.append(c1_tape.append_branch(6 * LAYER_ONE_LEN, flat))

            # Additional C1 layers
            for branch in data.branches_c1:
                pad = list(branch)
                while len(pad) < LAYER_ONE_LEN:
                    pad.append(HeliosField(0))
                c1_vars.append(c1_tape.append_branch(LAYER_ONE_LEN, pad))

            # Additional C2 layers
            for branch in data.branches_c2:
                pad = list(branch)
                while len(pad) < LAYER_TWO_LEN:
                    pad.append(SeleneField(0))
                c2_vars.append(c2_tape.append_branch(LAYER_TWO_LEN, pad))

            per_input_vars.append((c1_vars, c2_vars))

        # Root branch
        if isinstance(branches.root, RootBranchLeaves):
            flat = flatten_leaves(branches.root.outputs)
            root_vars = c1_tape.append_branch(len(flat), flat)
        elif isinstance(branches.root, RootBranchC1):
            pad = list(branches.root.branch)
            while len(pad) < LAYER_ONE_LEN:
                pad.append(HeliosField(0))
            root_vars = c1_tape.append_branch(LAYER_ONE_LEN, pad)
        else:
            pad = list(branches.root.branch)
            while len(pad) < LAYER_TWO_LEN:
                pad.append(SeleneField(0))
            root_vars = c2_tape.append_branch(LAYER_TWO_LEN, pad)

        return per_input_vars, root_vars

    # -----------------------------------------------------------------------
    # _transcript_inputs  (prover/mod.rs lines 390-489)
    # -----------------------------------------------------------------------

    @staticmethod
    def _transcript_inputs(branches: BranchesWithBlinds, c1_tape: VectorCommitmentTape) -> list:
        """Fill input blind claimed-points into c1_tape.

        Returns list of TranscriptedInput dicts, one per input.
        """
        params = OC_PARAMS  # Ed25519 / OcParameters
        sb = params.scalar_bits
        yx_c = params.yx_coefficients
        x_c = params.x_coefficients

        results = []
        for data in branches.per_input:
            ob = data.output_blinds
            o = ob.o_blind.inner  # PreparedBlind
            iu = ob.i_blind  # IBlind
            ibb = ob.i_blind_blind.inner  # PreparedBlind
            cb = ob.c_blind.inner  # PreparedBlind

            Ox, Oy = data.output.O[0], data.output.O[1]
            Ix, Iy = data.output.I[0], data.output.I[1]
            Cx, Cy = data.output.C[0], data.output.C[1]

            # Helper to convert Poly → tape dict
            def _div(smd: ScalarMulAndDivisor):
                return _poly_to_tape_dict(smd.divisor)

            # o_blind_claim: dlog=o.scalar.decomposition, point=(o.x, o.y), padding=[O.x, O.y]
            o_dlog_v, o_div_v, o_pt_v, o_pad_v = c1_tape.append_claimed_point(
                sb,
                yx_c,
                x_c,
                dlog=o.scalar.decomposition,
                divisor=_div(o.scalar_mul_and_divisor),
                point=(o.scalar_mul_and_divisor.x, o.scalar_mul_and_divisor.y),
                padding=[Ox, Oy],
            )
            o_blind_claim = PointWithDlog(
                dlog=o_dlog_v, divisor=Divisor.from_tape_dict(o_div_v), point=o_pt_v
            )
            O_vars = o_pad_v  # (Variable, Variable) for O.x, O.y

            # i_blind_u_claim: dlog=iu.scalar.decomposition, point=(iu.u.x, iu.u.y), padding=[I.x, I.y]
            iu_dlog_v, iu_div_v, iu_pt_v, iu_pad_v = c1_tape.append_claimed_point(
                sb,
                yx_c,
                x_c,
                dlog=iu.scalar.decomposition,
                divisor=_div(iu.u),
                point=(iu.u.x, iu.u.y),
                padding=[Ix, Iy],
            )
            i_blind_u_claim = PointWithDlog(
                dlog=iu_dlog_v, divisor=Divisor.from_tape_dict(iu_div_v), point=iu_pt_v
            )
            I_vars = iu_pad_v

            # i_blind_v divisor: extra slot = HeliosField(0)
            iv_div_v, iv_extra_v = c1_tape.append_divisor(
                yx_c,
                x_c,
                divisor=_div(iu.v),
                extra=HeliosField(0),
            )

            # i_blind_blind_claim: padding = i_blind_v point
            ivx, ivy = iu.v.x, iu.v.y
            ibb_dlog_v, ibb_div_v, ibb_pt_v, ibb_pad_v = c1_tape.append_claimed_point(
                sb,
                yx_c,
                x_c,
                dlog=ibb.scalar.decomposition,
                divisor=_div(ibb.scalar_mul_and_divisor),
                point=(ibb.scalar_mul_and_divisor.x, ibb.scalar_mul_and_divisor.y),
                padding=[ivx, ivy],
            )
            i_blind_blind_claim = PointWithDlog(
                dlog=ibb_dlog_v, divisor=Divisor.from_tape_dict(ibb_div_v), point=ibb_pt_v
            )
            i_blind_V_vars = ibb_pad_v  # (Variable, Variable) for i_blind_v.x, i_blind_v.y

            # i_blind_v_claim: shares dlog with i_blind_u_claim
            i_blind_v_claim = PointWithDlog(
                dlog=i_blind_u_claim.dlog,  # same list object (not a copy)
                divisor=Divisor.from_tape_dict(iv_div_v),
                point=(i_blind_V_vars[0], i_blind_V_vars[1]),
            )

            # c_blind_claim: padding = C coords
            cb_dlog_v, cb_div_v, cb_pt_v, cb_pad_v = c1_tape.append_claimed_point(
                sb,
                yx_c,
                x_c,
                dlog=cb.scalar.decomposition,
                divisor=_div(cb.scalar_mul_and_divisor),
                point=(cb.scalar_mul_and_divisor.x, cb.scalar_mul_and_divisor.y),
                padding=[Cx, Cy],
            )
            c_blind_claim = PointWithDlog(
                dlog=cb_dlog_v, divisor=Divisor.from_tape_dict(cb_div_v), point=cb_pt_v
            )
            C_vars = cb_pad_v

            results.append(
                {
                    "O": (O_vars[0], O_vars[1]),
                    "I": (I_vars[0], I_vars[1]),
                    "C": (C_vars[0], C_vars[1]),
                    "o_blind_claim": o_blind_claim,
                    "i_blind_u_claim": i_blind_u_claim,
                    "i_blind_v_claim": i_blind_v_claim,
                    "i_blind_blind_claim": i_blind_blind_claim,
                    "c_blind_claim": c_blind_claim,
                }
            )

        return results

    # -----------------------------------------------------------------------
    # _transcript_blinds  (prover/mod.rs lines 491-527)
    # -----------------------------------------------------------------------

    @staticmethod
    def _transcript_blinds(
        branches: BranchesWithBlinds, c1_tape: VectorCommitmentTape, c2_tape: VectorCommitmentTape
    ):
        """Fill cross-curve branch blind claimed-points."""
        c1_claims = []  # PointWithDlog entries placed in c1_tape (for C2 blinds)
        c2_claims = []  # PointWithDlog entries placed in c2_tape (for C1 blinds)

        c2p = C2_PARAMS  # C2Parameters (255 bits)
        c1p = C1_PARAMS  # C1Parameters (255 bits)

        # c1_tape opens C2 (Helios/HeliosField) branch blinds
        for blind in branches.branches_2_blinds:
            b = blind.inner  # PreparedBlind
            dv, ddiv, dpt, dpad = c1_tape.append_claimed_point(
                c2p.scalar_bits,
                c2p.yx_coefficients,
                c2p.x_coefficients,
                dlog=b.scalar.decomposition,
                divisor=_poly_to_tape_dict(b.scalar_mul_and_divisor.divisor),
                point=(b.scalar_mul_and_divisor.x, b.scalar_mul_and_divisor.y),
                padding=[],  # empty padding
            )
            c1_claims.append(
                PointWithDlog(dlog=dv, divisor=Divisor.from_tape_dict(ddiv), point=dpt)
            )

        # c2_tape opens C1 (Selene/SeleneField) branch blinds
        for blind in branches.branches_1_blinds:
            b = blind.inner  # PreparedBlind
            dv, ddiv, dpt, dpad = c2_tape.append_claimed_point(
                c1p.scalar_bits,
                c1p.yx_coefficients,
                c1p.x_coefficients,
                dlog=b.scalar.decomposition,
                divisor=_poly_to_tape_dict(b.scalar_mul_and_divisor.divisor),
                point=(b.scalar_mul_and_divisor.x, b.scalar_mul_and_divisor.y),
                padding=[],
            )
            c2_claims.append(
                PointWithDlog(dlog=dv, divisor=Divisor.from_tape_dict(ddiv), point=dpt)
            )

        return c1_claims, c2_claims  # (c1_blind_claims for C2, c2_blind_claims for C1)

    # -----------------------------------------------------------------------
    # _compute_tree_root  (lib.rs lines 576-607)
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_tree_root(branches: BranchesWithBlinds, params: FcmpParams):
        """Compute the tree root point.
        Returns (is_c1: bool, root_bytes: bytes, root_wpt: WPoint).
        """
        root = branches.root
        g1 = params.curve_1_generators.g_bold_slice()
        g2 = params.curve_2_generators.g_bold_slice()
        h1 = params.curve_1_hash_init
        h2 = params.curve_2_hash_init
        identity_c1 = WPoint.identity(h1.field_cls, h1.B)
        identity_c2 = WPoint.identity(h2.field_cls, h2.B)

        if isinstance(root, RootBranchLeaves):
            # 6 scalars per output in order [O.x, O.y, I.x, I.y, C.x, C.y]
            scalars = []
            for out in root.outputs:
                scalars.extend([out.O[0], out.O[1], out.I[0], out.I[1], out.C[0], out.C[1]])
            pairs = list(zip(scalars, g1[: len(scalars)]))
            root_pt = h1 + _multiexp(pairs, identity_c1)
            return (True, point_to_bytes(root_pt), root_pt)

        elif isinstance(root, RootBranchC1):
            pairs = list(zip(root.branch, g1[: len(root.branch)]))
            root_pt = h1 + _multiexp(pairs, identity_c1)
            return (True, point_to_bytes(root_pt), root_pt)

        else:  # RootBranchC2
            pairs = list(zip(root.branch, g2[: len(root.branch)]))
            root_pt = h2 + _multiexp(pairs, identity_c2)
            return (False, point_to_bytes(root_pt), root_pt)

    # -----------------------------------------------------------------------
    # _input  (lib.rs lines 394-557)
    # -----------------------------------------------------------------------

    @staticmethod
    def _input(
        params: FcmpParams,
        layers: int,
        transcript: ProverTranscript,
        c1_circuit,
        c1_dlog_challenge,
        c2_circuit,
        c2_dlog_challenge,
        root_vars: list,
        c1_branch_vars: list,
        c2_branch_vars: list,
        c2_commitments_iter,  # feeds C1 branches (C2 pts + C2 blinds + C1 blind claims)
        c1_commitments_iter,  # feeds C2 branches (C1 pts + C1 blinds + C2 blind claims)
        input_tuple: dict,
        transcripted_input: dict,
    ):
        """Process one input through all circuit layers.

        Mirrors Fcmp::input() in lib.rs.
        """
        from divisors import WEI25519_A

        c1_branch_iter = iter(c1_branch_vars)
        c2_branch_iter = iter(c2_branch_vars)

        from divisors import WEI25519_B
        from curve import SELENE_B, HELIOS_B

        # OC: Wei25519 (a = WEI25519_A, b = WEI25519_B, both in HeliosField)
        oc_spec = CurveSpec(HeliosField(WEI25519_A), HeliosField(WEI25519_B))
        # C1 (Selene): a = -3, b = SELENE_B in SeleneField
        c1_spec = CurveSpec(SeleneField(SeleneField.P - 3), SELENE_B)
        # C2 (Helios): a = -3, b = HELIOS_B in HeliosField
        c2_spec = CurveSpec(HeliosField(HeliosField.P - 3), HELIOS_B)

        amount_c1_branches = (layers // 2) + (layers % 2)
        amount_non_leaf_c1 = amount_c1_branches - 1
        amount_c2_branches = layers // 2
        root_is_c1 = (layers % 2) == 1

        # First layer — establishes membership and proves the input tuple
        ti = transcripted_input
        leaf_vars = root_vars if layers == 1 else next(c1_branch_iter)
        leaf_chunks = [leaf_vars[i * 6 : (i + 1) * 6] for i in range(len(leaf_vars) // 6)]

        c1_circuit.first_layer(
            transcript,
            oc_spec,
            params.T_table,
            params.U_table,
            params.V_table,
            params.G_table,
            input_tuple["O_tilde"],
            ti["o_blind_claim"],
            ti["O"],
            input_tuple["I_tilde"],
            ti["i_blind_u_claim"],
            ti["I"],
            input_tuple["R"],
            ti["i_blind_v_claim"],
            ti["i_blind_blind_claim"],
            input_tuple["C_tilde"],
            ti["c_blind_claim"],
            ti["C"],
            leaf_chunks,
        )

        # Populate challenges if not yet set
        if c1_dlog_challenge[0] is None and amount_non_leaf_c1 > 0:
            c1_dlog_challenge[0] = c1_circuit.additional_layer_discrete_log_challenge(
                transcript, c2_spec, params.H_2_table
            )

        if c2_dlog_challenge[0] is None and amount_c2_branches > 0:
            c2_dlog_challenge[0] = c2_circuit.additional_layer_discrete_log_challenge(
                transcript, c1_spec, params.H_1_table
            )

        # Build per-input branch chain (excluding leaf already consumed)
        non_root_c1 = amount_non_leaf_c1 - (1 if root_is_c1 else 0)
        non_root_c2 = amount_c2_branches - (0 if root_is_c1 else 1)

        these_c1 = [next(c1_branch_iter) for _ in range(non_root_c1)]
        these_c2 = [next(c2_branch_iter) for _ in range(non_root_c2)]

        # Only add root_vars to the additional_layer loop when there is more than the leaf.
        # For layers=1, amount_c1_branches=1 and the leaf was already handled by first_layer.
        if root_is_c1 and amount_c1_branches > 1:
            these_c1.append(root_vars)
        elif not root_is_c1:
            these_c2.append(root_vars)

        # C1 branches open C2 commitments
        # each item = ((C2_pt, C2_blind), C2_blind_claim)
        for branch_vars in these_c1:
            (prior_c2_pt, prior_c2_blind), blind_opening = next(c2_commitments_iter)
            # add C2 hash_init before everything
            prior_c = prior_c2_pt + params.curve_2_hash_init
            #  free mul gate; witness = coords of hash point (prior_c minus blind*H)
            if prior_c2_blind is not None:
                h2 = params.curve_2_generators.h()
                # prior_c − blind·H  (using WPoint.__mul__ and __neg__)
                hash_pt = prior_c + (-(h2 * int(prior_c2_blind)))
                hash_witness = (hash_pt.x, hash_pt.y)  # HeliosField elements
            else:
                hash_witness = None
            hash_x, hash_y, _ = c1_circuit.mul(None, None, hash_witness)
            c1_circuit.additional_layer(
                c2_spec,
                c1_dlog_challenge[0],
                (prior_c.x, prior_c.y),  # C2 point coords as HeliosField
                blind_opening,
                (hash_x, hash_y),
                branch_vars,
            )

        # C2 branches open C1 commitments
        # each item = ((C1_pt, C1_blind), C1_blind_claim)
        for branch_vars in these_c2:
            (prior_c1_pt, prior_c1_blind), blind_opening = next(c1_commitments_iter)
            # add C1 hash_init before everything
            prior_c = prior_c1_pt + params.curve_1_hash_init
            if prior_c1_blind is not None:
                h1 = params.curve_1_generators.h()
                hash_pt = prior_c + (-(h1 * int(prior_c1_blind)))
                hash_witness = (hash_pt.x, hash_pt.y)  # SeleneField elements
            else:
                hash_witness = None
            hash_x, hash_y, _ = c2_circuit.mul(None, None, hash_witness)
            c2_circuit.additional_layer(
                c1_spec,
                c2_dlog_challenge[0],
                (prior_c.x, prior_c.y),  # C1 point coords as SeleneField
                blind_opening,
                (hash_x, hash_y),
                branch_vars,
            )

    # -----------------------------------------------------------------------
    # prove  (lib.rs lines 567-821)
    # -----------------------------------------------------------------------

    @classmethod
    def prove(cls, rng_seed: int, params: FcmpParams, branches: BranchesWithBlinds) -> "Fcmp":
        """Prove a full-chain membership proof.

        rng_seed: integer seed for deterministic random number generation (for testing).

        """
        import secrets

        def _random_field_c1():
            return HeliosField(int.from_bytes(secrets.token_bytes(64), "little") % HeliosField.P)

        def _random_field_c2():
            return SeleneField(
                int.from_bytes(secrets.token_bytes(64), "little") % SeleneField.P
            )

        # Compute tree root and determine which curve it's on
        is_c1, root_bytes, root_wpt = cls._compute_tree_root(branches, params)

        n_inputs = len(branches.per_input)
        data0 = branches.per_input[0]
        layers = (
            (1 if data0.leaves is not None else 0)
            + len(data0.branches_c1)
            + len(data0.branches_c2)
            + 1
        )

        c1_padded, c2_padded = cls.ipa_rows(n_inputs, layers)

        # Create tapes
        c1_tape = VectorCommitmentTape(HeliosField, c1_padded)
        c2_tape = VectorCommitmentTape(SeleneField, c2_padded)

        # Fill tapes
        per_input_vars, root_vars = cls._transcript_branches(branches, c1_tape, c2_tape)
        transcripted_inputs = cls._transcript_inputs(branches, c1_tape)
        c1_blind_claims, c2_blind_claims = cls._transcript_blinds(branches, c1_tape, c2_tape)

        # Build pvc_blinds — branch blinds are negated
        # ScalarDecomposition.scalar is already a Python int
        pvc_blinds_1 = [-b.inner.scalar.scalar % HeliosField.P for b in branches.branches_1_blinds]
        pvc_blinds_2 = [
            -b.inner.scalar.scalar % SeleneField.P for b in branches.branches_2_blinds
        ]

        # Convert to field elements
        pvc_blinds_1 = [HeliosField(v) for v in pvc_blinds_1]
        pvc_blinds_2 = [SeleneField(v) for v in pvc_blinds_2]

        # Fill remaining blind slots with random values (after branch blinds)
        while len(pvc_blinds_1) < len(c1_tape.commitments):
            pvc_blinds_1.append(_random_field_c1())
        while len(pvc_blinds_2) < len(c2_tape.commitments):
            pvc_blinds_2.append(_random_field_c2())

        # Root blind index = len(branches_*_blinds)
        if is_c1:
            root_blind = pvc_blinds_1[len(branches.branches_1_blinds)]
        else:
            root_blind = pvc_blinds_2[len(branches.branches_2_blinds)]

        # Compute PVC commitments
        g1 = params.curve_1_generators.g_bold_slice()
        h1 = params.curve_1_generators.h()
        g2 = params.curve_2_generators.g_bold_slice()
        h2 = params.curve_2_generators.h()

        commitments_1 = c1_tape.commit(g1, h1, pvc_blinds_1)
        commitments_2 = c2_tape.commit(g2, h2, pvc_blinds_2)

        # Root blind PoK nonce R = r·H
        if is_c1:
            root_r = _random_field_c1()
            root_blind_R_pt = h1 * int(root_r)
        else:
            root_r = _random_field_c2()
            root_blind_R_pt = h2 * int(root_r)
        root_blind_R = point_to_bytes(root_blind_R_pt)

        # Compute input tuples (blinded) for the transcript hash
        input_tuples = []
        for data in branches.per_input:
            blinded = data.output_blinds.blind(data.output.O, data.output.I, data.output.C)
            input_tuples.append(blinded)

        # Outer transcript hash
        ctx = cls.transcript(is_c1, root_bytes, input_tuples, root_blind_R)

        # GBP transcript
        transcript = ProverTranscript(ctx)

        # Two separate write_commitments calls: C1 then C2
        # write_commitments returns (C_list, V_list); keep the raw point list for later
        raw_commitments_1, _ = transcript.write_commitments(commitments_1, [])
        raw_commitments_2, _ = transcript.write_commitments(commitments_2, [])

        # Schnorr challenge (c = challenge AFTER write_commitments)
        if is_c1:
            c = transcript.challenge(HeliosField)
            s = HeliosField((int(root_r) + int(c) * int(root_blind)) % HeliosField.P)
        else:
            c = transcript.challenge(SeleneField)
            s = SeleneField((int(root_r) + int(c) * int(root_blind)) % SeleneField.P)

        # root_blind_pok = root_blind_R[0:32] || s[0:32]
        root_blind_pok = root_blind_R + s.to_bytes()

        # Create circuits  (Circuit.prove takes field_cls + list of PedersenVectorCommitment)
        c1_pvc_list = [
            PedersenVectorCommitment(vals, b) for vals, b in zip(c1_tape.commitments, pvc_blinds_1)
        ]
        c2_pvc_list = [
            PedersenVectorCommitment(vals, b) for vals, b in zip(c2_tape.commitments, pvc_blinds_2)
        ]
        c1_circuit = Circuit.prove(HeliosField, c1_pvc_list)
        c2_circuit = Circuit.prove(SeleneField, c2_pvc_list)

        # Shared dlog challenge holders (mutable single-element lists)
        c1_dlog_ch = [None]
        c2_dlog_ch = [None]

        # Cross-curve commitment iterators :
        #   c1_commitments = (C1_point, C1_blind) zip C2_blind_claims
        #   These feed into the c2 branches (C2 branches open C1 commitments)
        #   c2_commitments = (C2_point, C2_blind) zip C1_blind_claims
        #   These feed into the c1 branches (C1 branches open C2 commitments)
        c1_commit_iter = iter(
            zip(
                zip(raw_commitments_1, pvc_blinds_1),  # (C1_pt, C1_blind)
                c2_blind_claims,  # C2 blind claims in c1_tape
            )
        )
        c2_commit_iter = iter(
            zip(
                zip(raw_commitments_2, pvc_blinds_2),  # (C2_pt, C2_blind)
                c1_blind_claims,  # C1 blind claims in c2_tape
            )
        )

        # Process each input; each input gets its own branch var lists
        for idx, (data, ti) in enumerate(zip(branches.per_input, transcripted_inputs)):
            c1_vars, c2_vars = per_input_vars[idx]
            input_layers = len(c1_vars) + len(c2_vars) + 1
            blinded = data.output_blinds.blind(data.output.O, data.output.I, data.output.C)

            cls._input(
                params,
                input_layers,
                transcript,
                c1_circuit,
                c1_dlog_ch,
                c2_circuit,
                c2_dlog_ch,
                root_vars,
                c1_vars,
                c2_vars,
                c2_commit_iter,  # C1 branches open C2 commitments
                c1_commit_iter,  # C2 branches open C1 commitments
                blinded,
                ti,
            )

        # Build arithmetic circuit statements and prove GBP
        c1_gens = params.curve_1_generators.reduce(c1_padded)
        c2_gens = params.curve_2_generators.reduce(c2_padded)

        c1_stmt, c1_witness = c1_circuit.statement(c1_gens, raw_commitments_1)
        c2_stmt, c2_witness = c2_circuit.statement(c2_gens, raw_commitments_2)

        c1_stmt.prove(_random_field_c1, transcript, c1_witness, HeliosField)
        c2_stmt.prove(_random_field_c2, transcript, c2_witness, SeleneField)

        proof = transcript.complete()
        return cls(proof, root_blind_pok)

    # -----------------------------------------------------------------------
    # verify  (lib.rs lines 839-1063)
    # -----------------------------------------------------------------------

    @classmethod
    def verify(
        cls,
        proof: bytes,
        root_blind_pok: bytes,
        params: FcmpParams,
        is_c1: bool,
        tree_root_bytes: bytes,
        layers: int,
        inputs: list,
        verifier_1,
        verifier_2,
        rng_fn,
    ) -> None:
        """Queue a FCMP for batch verification.

        proof          : proof bytes (from Fcmp.proof)
        root_blind_pok : 64-byte Schnorr PoK (from Fcmp.root_blind_pok)
        params         : FcmpParams
        is_c1          : True if tree root is on C1 (Selene), False for C2 (Helios)
        tree_root_bytes: 32-byte compressed root point
        layers         : tree depth (>= 1)
        inputs         : list of dicts with 'O_tilde','I_tilde','R','C_tilde' as
                         (HeliosField,HeliosField) tuples
        verifier_1     : BatchVerifier for C1 (caller creates, must be finalized after)
        verifier_2     : BatchVerifier for C2
        rng_fn         : callable() -> field element for batch weighting
        """
        from itertools import repeat
        from curve import selene_from_bytes, helios_from_bytes
        from transcript import VerifierTranscript

        n_inputs = len(inputs)
        c1_padded, c2_padded = cls.ipa_rows(n_inputs, layers)

        # -------------------------------------------------------------------
        # Build tapes (no witness)  — flat branch loop
        # -------------------------------------------------------------------
        c1_tape = VectorCommitmentTape(HeliosField, c1_padded)
        c2_tape = VectorCommitmentTape(SeleneField, c2_padded)

        c1_branches_flat = []
        c2_branches_flat = []
        for _ in range(n_inputs):
            for i in range(layers - 1):
                if i % 2 == 0:
                    blen = 6 * LAYER_ONE_LEN if i == 0 else LAYER_ONE_LEN
                    c1_branches_flat.append(c1_tape.append_branch(blen, None))
                else:
                    c2_branches_flat.append(c2_tape.append_branch(LAYER_TWO_LEN, None))

        # Root branch
        root_is_c1 = (layers % 2) == 1
        if root_is_c1:
            root_len = 6 * LAYER_ONE_LEN if layers == 1 else LAYER_ONE_LEN
            root_vars = c1_tape.append_branch(root_len, None)
        else:
            root_vars = c2_tape.append_branch(LAYER_TWO_LEN, None)

        # -------------------------------------------------------------------
        # Transcript inputs (verifier — all None witnesses)
        # -------------------------------------------------------------------
        sb = OC_PARAMS.scalar_bits
        yx_c = OC_PARAMS.yx_coefficients
        x_c = OC_PARAMS.x_coefficients

        def _acp_oc():
            return c1_tape.append_claimed_point(sb, yx_c, x_c, None, None, None, None)

        input_openings = []
        for _ in range(n_inputs):
            dv_o, dd_o, pt_o, pad_o = _acp_oc()
            o_blind_claim = PointWithDlog(
                dlog=dv_o, divisor=Divisor.from_tape_dict(dd_o), point=pt_o
            )
            O_vars = pad_o

            dv_u, dd_u, pt_u, pad_u = _acp_oc()
            i_blind_u_claim = PointWithDlog(
                dlog=dv_u, divisor=Divisor.from_tape_dict(dd_u), point=pt_u
            )
            I_vars = pad_u

            # i_blind_v: divisor only; extra = F::ZERO
            iv_div, _iv_extra = c1_tape.append_divisor(yx_c, x_c, None, None)

            # i_blind_blind: padding = i_blind_v point
            dv_bb, dd_bb, pt_bb, pad_bb = _acp_oc()
            i_blind_blind_claim = PointWithDlog(
                dlog=dv_bb, divisor=Divisor.from_tape_dict(dd_bb), point=pt_bb
            )
            i_blind_V_vars = pad_bb

            # i_blind_v: shares dlog with i_blind_u
            i_blind_v_claim = PointWithDlog(
                dlog=i_blind_u_claim.dlog,
                divisor=Divisor.from_tape_dict(iv_div),
                point=(i_blind_V_vars[0], i_blind_V_vars[1]),
            )

            dv_c, dd_c, pt_c, pad_c = _acp_oc()
            c_blind_claim = PointWithDlog(
                dlog=dv_c, divisor=Divisor.from_tape_dict(dd_c), point=pt_c
            )
            C_vars = pad_c

            input_openings.append(
                {
                    "O": (O_vars[0], O_vars[1]),
                    "I": (I_vars[0], I_vars[1]),
                    "C": (C_vars[0], C_vars[1]),
                    "o_blind_claim": o_blind_claim,
                    "i_blind_u_claim": i_blind_u_claim,
                    "i_blind_v_claim": i_blind_v_claim,
                    "i_blind_blind_claim": i_blind_blind_claim,
                    "c_blind_claim": c_blind_claim,
                }
            )

        # -------------------------------------------------------------------
        # Blind claims
        # C1 tape holds C2 blind claims; C2 tape holds C1 blind claims
        # -------------------------------------------------------------------
        c2p = C2_PARAMS
        c1p = C1_PARAMS

        # C2 blinds in c1_tape
        if len(c1_branches_flat) == 0:
            n_c1_blind_claims = 0
        else:
            n_non_leaf_c1 = len(c1_branches_flat) - n_inputs
            n_c1_blind_claims = n_non_leaf_c1 + (n_inputs if is_c1 else 0)

        c1_blind_claims = []
        for _ in range(n_c1_blind_claims):
            dv, ddiv, dpt, _ = c1_tape.append_claimed_point(
                c2p.scalar_bits, c2p.yx_coefficients, c2p.x_coefficients, None, None, None, None
            )
            c1_blind_claims.append(
                PointWithDlog(dlog=dv, divisor=Divisor.from_tape_dict(ddiv), point=dpt)
            )

        # C1 blinds in c2_tape
        n_c2_blind_claims = len(c2_branches_flat) + (0 if is_c1 else n_inputs)

        c2_blind_claims = []
        for _ in range(n_c2_blind_claims):
            dv, ddiv, dpt, _ = c2_tape.append_claimed_point(
                c1p.scalar_bits, c1p.yx_coefficients, c1p.x_coefficients, None, None, None, None
            )
            c2_blind_claims.append(
                PointWithDlog(dlog=dv, divisor=Divisor.from_tape_dict(ddiv), point=dpt)
            )

        # -------------------------------------------------------------------
        # VerifierTranscript + read commitments
        # -------------------------------------------------------------------
        ctx = cls.transcript(is_c1, tree_root_bytes, inputs, root_blind_pok[:32])
        transcript = VerifierTranscript(ctx, proof)

        C1_pts, _ = transcript.read_commitments(len(c1_tape.commitments), 0, selene_from_bytes)
        C2_pts, _ = transcript.read_commitments(len(c2_tape.commitments), 0, helios_from_bytes)

        # -------------------------------------------------------------------
        # Root blind PoK verification
        # claimed = hash_init + C_pts[root_vars[0].commitment]
        # Equation: R + c*(claimed - actual) == s*H  (batch-weighted)
        # -------------------------------------------------------------------
        root_cidx = root_vars[0].commitment  # use Variable.commitment, not index 0
        if is_c1:
            claimed_root_pt = params.curve_1_hash_init + C1_pts[root_cidx]
            actual_root_pt = selene_from_bytes(tree_root_bytes)
            R_pt = selene_from_bytes(root_blind_pok[:32])
            s = HeliosField.from_bytes(root_blind_pok[32:64])
            c = transcript.challenge(HeliosField)
            w = HeliosField(int(rng_fn()))  # C1 (Selene) scalar = HeliosField
            verifier_1.additional.append((w, R_pt))
            verifier_1.additional.append((w * c, claimed_root_pt + (-actual_root_pt)))
            verifier_1.h = verifier_1.h - s * w
        else:
            claimed_root_pt = params.curve_2_hash_init + C2_pts[root_cidx]
            actual_root_pt = helios_from_bytes(tree_root_bytes)
            R_pt = helios_from_bytes(root_blind_pok[:32])
            s = SeleneField.from_bytes(root_blind_pok[32:64])
            c = transcript.challenge(SeleneField)
            w = SeleneField(int(rng_fn()))  # C2 (Helios) scalar = SeleneField
            verifier_2.additional.append((w, R_pt))
            verifier_2.additional.append((w * c, claimed_root_pt + (-actual_root_pt)))
            verifier_2.h = verifier_2.h - s * w

        # -------------------------------------------------------------------
        # Verifier circuits
        # -------------------------------------------------------------------
        c1_circuit = Circuit.verify(HeliosField)
        c2_circuit = Circuit.verify(SeleneField)
        c1_dlog_ch = [None]
        c2_dlog_ch = [None]

        # Cross-curve commitment iterators
        # c2_commit_iter -> C1 branches open C2 commitments
        c2_commit_iter = iter(
            zip(
                zip(C2_pts, repeat(None)),
                c1_blind_claims,
            )
        )
        # c1_commit_iter -> C2 branches open C1 commitments
        c1_commit_iter = iter(
            zip(
                zip(C1_pts, repeat(None)),
                c2_blind_claims,
            )
        )

        # Per-input slices of flat branch lists
        c1_per_inp = layers // 2
        c2_per_inp = (layers - 1) // 2

        # -------------------------------------------------------------------
        # Process each input
        # -------------------------------------------------------------------
        for idx, (inp_data, opening) in enumerate(zip(inputs, input_openings)):
            c1_vars = c1_branches_flat[idx * c1_per_inp : (idx + 1) * c1_per_inp]
            c2_vars = c2_branches_flat[idx * c2_per_inp : (idx + 1) * c2_per_inp]

            cls._input(
                params,
                layers,
                transcript,
                c1_circuit,
                c1_dlog_ch,
                c2_circuit,
                c2_dlog_ch,
                root_vars,
                c1_vars,
                c2_vars,
                c2_commit_iter,
                c1_commit_iter,
                inp_data,
                opening,
            )

        # -------------------------------------------------------------------
        # AC statements + batch verification
        # -------------------------------------------------------------------
        c1_gens = params.curve_1_generators.reduce(c1_padded)
        c2_gens = params.curve_2_generators.reduce(c2_padded)

        # Wrap rng_fn to always yield the correct field type for each circuit.
        # C1 (Selene) scalar field = HeliosField; C2 (Helios) scalar field = SeleneField.
        def _rng_c1():
            return HeliosField(int(rng_fn()))

        def _rng_c2():
            return SeleneField(int(rng_fn()))

        c1_stmt, _ = c1_circuit.statement(c1_gens, C1_pts)
        c1_stmt.verify(_rng_c1, verifier_1, transcript, HeliosField, selene_from_bytes)

        c2_stmt, _ = c2_circuit.statement(c2_gens, C2_pts)
        c2_stmt.verify(_rng_c2, verifier_2, transcript, SeleneField, helios_from_bytes)

        if not transcript.is_exhausted():
            raise ValueError(
                f"proof has {len(transcript._proof) - transcript._pos} trailing bytes — "
                "possible proof malleability or parsing error"
            )


# ---------------------------------------------------------------------------
# Helpers for coordinate extraction from WPoint
# ---------------------------------------------------------------------------


def _wpoint_to_xy_helios(pt: WPoint):
    x, y = pt.to_affine()
    return (HeliosField(x), HeliosField(y))


def _wpoint_to_xy_helioselene(pt: WPoint):
    x, y = pt.to_affine()
    return (SeleneField(x), SeleneField(y))
