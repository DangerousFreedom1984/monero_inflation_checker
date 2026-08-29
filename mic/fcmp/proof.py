"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

proof.py - the FCMP++ membership proof: Fcmp.prove and Fcmp.verify 

prove: BIND, ARITHMETIZE, COMMIT, ARGUE, SERIALIZE.
verify: RECONSTRUCT, REPLAY, CHECK 

The rest of the file is what those two consume: the blinds (ScalarMulAndDivisor,
PreparedBlind, OBlind/IBlind/IBlindBlind/CBlind, OutputBlinds, BranchBlind), the
tree path per input (Output, PerInputData, BranchesWithBlinds), the consensus
generators (FcmpParams), and the transcript that binds root, inputs and blinds.
"""

import hashlib


from mic.fcmp.field import HeliosField, SeleneField
from mic.fcmp.curve import HELIOS, SELENE, WEI25519, WEI25519_A, WPoint, point_to_bytes
from mic.fcmp.tape import VectorCommitmentTape
from mic.fcmp.circuit import (
    Circuit,
    CurveSpec,
    GeneratorTable,
    OC_PARAMS,
    C1_PARAMS,
    C2_PARAMS,
    PointWithDlog,
    Divisor,
)
from mic.fcmp.divisors import ScalarDecomposition
from mic.fcmp.polynomial import Poly
from mic.fcmp.multiexp import multiexp as _multiexp
from mic.fcmp.gbp import PedersenVectorCommitment, ProverTranscript, VerifierTranscript

LAYER_ONE_LEN = 38
LAYER_TWO_LEN = 18

_C1_LEAVES_ROWS = 97
_C1_BRANCH_ROWS = 52
_C2_ROWS_PER_LAYER = 32
_C1_TARGET = 256
_C2_TARGET = 128


def _next_pow2(n: int) -> int:
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def _poly_to_tape_dict(poly: Poly):
    """Convert a Poly object to the dict format consumed by tape.append_divisor()."""
    y_val = poly.y[0] if poly.y else None
    yx_list = list(poly.yx[0]) if poly.yx else []
    x_list = list(poly.x)  # x[0] = 1 (normalized), tape skips x[0]
    return {
        "y": y_val,
        "yx": yx_list,
        "x": x_list,
        "zero": poly.zero,
    }


# ===========================================================================
# Scalar-mul-and-divisor
# ===========================================================================


class ScalarMulAndDivisor:
    """Precomputed scalar * generator, its coordinates, and the divisor polynomial.

    For OC curve: generator is a ProjectivePoint on Wei25519, coordinates are HeliosField.
    For C1 curve: generator is WPoint(Selene), coordinates are SeleneField.
    For C2 curve: generator is WPoint(Helios), coordinates are HeliosField.
    """

    def __init__(self, point, x, y, divisor: Poly):
        self.point = point  # curve point (ProjectivePoint or WPoint)
        self.x = x  # field element (x-coordinate)
        self.y = y  # field element (y-coordinate)
        self.divisor = divisor  # Poly with x[0]=1 (normalize_x_coefficient already applied)

    @classmethod
    def new_oc(cls, A_wei, scalar_decomp: ScalarDecomposition):
        """Build for OC (Wei25519).

        A_wei       : ProjectivePoint on Wei25519, the generator
        scalar_decomp: ScalarDecomposition over Ed25519 scalars
        """
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
        divisor = scalar_decomp.scalar_mul_divisor(SELENE.point(A.x.v, A.y.v))
        return cls(p, SeleneField(p.x.v), SeleneField(p.y.v), divisor)

    @classmethod
    def new_c2(cls, A: WPoint, scalar_decomp: ScalarDecomposition):
        """Build for C2 (Helios).

        A           : WPoint on Helios
        scalar_decomp: ScalarDecomposition (must be over the C2 scalar field = SeleneField)
        """
        p = A * scalar_decomp.scalar
        divisor = scalar_decomp.scalar_mul_divisor(HELIOS.point(A.x.v, A.y.v))
        return cls(p, HeliosField(p.x.v), HeliosField(p.y.v), divisor)


class PreparedBlind:
    """A blind scalar + its scalar-mul-and-divisor result."""

    def __init__(self, scalar: ScalarDecomposition, scalar_mul_and_divisor: ScalarMulAndDivisor):
        self.scalar = scalar
        self.scalar_mul_and_divisor = scalar_mul_and_divisor


# ---------------------------------------------------------------------------
# Typed blind wrappers
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
    P = HeliosField.P
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + WEI25519_A) * pow(2 * y1, P - 2, P) % P
    else:
        m = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


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
    """An output tuple (O, I, C) on the OC curve: affine (x, y) as HeliosField pairs."""

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
# Root branch options
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


class Fcmp:
    """Full-chain membership proof."""

    def __init__(self, proof: bytes, root_blind_pok: bytes):
        if len(root_blind_pok) != 64:
            raise ValueError(f"root_blind_pok must be 64 bytes, got {len(root_blind_pok)}")
        self.proof = proof
        self.root_blind_pok = root_blind_pok


    @staticmethod
    def ipa_rows(inputs: int, layers: int) -> tuple:
        """Compute (c1_padded, c2_padded) for IPA round counts."""
        non_leaves_c1 = max(layers - 1, 0) // 2
        c1_rows = inputs * (_C1_LEAVES_ROWS + non_leaves_c1 * _C1_BRANCH_ROWS)
        c2_rows = inputs * max(layers // 2 * _C2_ROWS_PER_LAYER, 1)
        c1_rows = max(_next_pow2(c1_rows), _C1_TARGET)
        c2_rows = max(_next_pow2(c2_rows), _C2_TARGET)
        return (c1_rows, c2_rows)


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


    @staticmethod
    def _transcript_branches(
        branches: BranchesWithBlinds, c1_tape: VectorCommitmentTape, c2_tape: VectorCommitmentTape
    ):
        """Fill branch data into c1_tape and c2_tape.

        Mirrors transcript_branches() exactly:
          - For each input: optional leaf branch → c1_layers → c2_layers
          - Then the root branch (separate)

        For 1-layer trees: leaves=None per-input, root=RootBranchLeaves.

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

        """
        c1_branch_iter = iter(c1_branch_vars)
        c2_branch_iter = iter(c2_branch_vars)

        oc_spec = CurveSpec.for_curve(WEI25519)
        c1_spec = CurveSpec.for_curve(SELENE)
        c2_spec = CurveSpec.for_curve(HELIOS)

        amount_c1_branches = (layers // 2) + (layers % 2)
        amount_non_leaf_c1 = amount_c1_branches - 1
        amount_c2_branches = layers // 2
        root_is_c1 = (layers % 2) == 1

        # First layer: establishes membership and proves the input tuple
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
            #  free mul gate, witness = coords of hash point (prior_c minus blind*H)
            if prior_c2_blind is not None:
                h2 = params.curve_2_generators.h()
                # prior_c − blind·H  (using WPoint.__mul__ and __neg__)
                hash_pt = prior_c + (-(h2 * int(prior_c2_blind)))
                hash_witness = (hash_pt.x, hash_pt.y)  # HeliosField elements
            else:
                hash_witness = None
            hash_x, hash_y = c1_circuit.new_wires(hash_witness)
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
            hash_x, hash_y = c2_circuit.new_wires(hash_witness)
            c2_circuit.additional_layer(
                c1_spec,
                c2_dlog_challenge[0],
                (prior_c.x, prior_c.y),  # C1 point coords as SeleneField
                blind_opening,
                (hash_x, hash_y),
                branch_vars,
            )

    # Five phases, in the order the Fiat-Shamir transcript forces:
    #
    #   1. BIND        the tree root, which says which set membership is claimed in
    #   2. ARITHMETIZE lay the witness out on the two per-curve commitment tapes
    #   3. COMMIT      form the vector commitments, and the root-blind Schnorr PoK.
    #                  Hashing all of that fixes the transcript context
    #   4. ARGUE       build the two R1CS systems and run Generalized Bulletproofs
    #   5. SERIALIZE   the transcript's write buffer is the proof
    #

    @classmethod
    def prove(cls, rng_seed: int, params: FcmpParams, branches: BranchesWithBlinds) -> "Fcmp":
        """Prove that each input's output is in the tree, without revealing which.

        branches carries, per input, the output being spent, its re-randomization
        blinds, and the tree path from its leaf to the root, plus one blind per
        branch. 

        Returns the Fcmp proof: the membership proof bytes and the 64-byte
        root-blind proof of knowledge.
        """
        rand_c1, rand_c2 = cls._blind_sources()

        # -- 1. BIND ------------------------------------------------------
        is_c1, root_bytes, _root_pt = cls._compute_tree_root(branches, params)
        n_inputs = len(branches.per_input)
        layers = cls._tree_depth(branches)

        # -- 2. ARITHMETIZE -----------------------------------------------
        tapes = cls._arithmetize(branches, n_inputs, layers)

        # -- 3. COMMIT ----------------------------------------------------
        commitments = cls._commit(params, branches, tapes, is_c1, rand_c1, rand_c2)
        transcript, root_blind_pok = cls._open_transcript(
            branches, commitments, is_c1, root_bytes, rand_c1, rand_c2
        )

        # -- 4. ARGUE -----------------------------------------------------
        circuits = cls._build_circuits(params, branches, tapes, commitments, transcript)
        cls._run_gbp(params, tapes, circuits, commitments, transcript, rand_c1, rand_c2)

        # -- 5. SERIALIZE -------------------------------------------------
        return cls(transcript.complete(), root_blind_pok)

    # -- phase helpers ----------------------------------------------------

    @staticmethod
    def _blind_sources():
        """Uniform field elements for the two curves, from OS randomness.

        Wide (64-byte) reduction, so the result is statistically uniform in the
        field rather than biased toward its low end.
        """
        import secrets

        def rand_c1():
            return HeliosField(int.from_bytes(secrets.token_bytes(64), "little") % HeliosField.P)

        def rand_c2():
            return SeleneField(int.from_bytes(secrets.token_bytes(64), "little") % SeleneField.P)

        return rand_c1, rand_c2

    @staticmethod
    def _tree_depth(branches: BranchesWithBlinds) -> int:
        """Tree depth implied by one input's path: leaf layer + interior + root."""
        data = branches.per_input[0]
        # At depth 1 the leaf layer is the root, so there is no separate leaf branch.
        return (
            (1 if data.leaves is not None else 0)
            + len(data.branches_c1)
            + len(data.branches_c2)
            + 1
        )

    @classmethod
    def _arithmetize(cls, branches: BranchesWithBlinds, n_inputs: int, layers: int):
        """Lay the whole witness out on the two per-curve commitment tapes.

        A "tape" is the flat vector each Pedersen vector commitment commits to. Every
        secret the circuit will reference (branch contents, the blinds' scalar
        decompositions and divisors, the claimed points) gets a slot here, and the
        slot index is the wire name the gadgets later constrain (CG(ci, j)).

        The tape is padded to a power of two (ipa_rows) because the inner-product
        argument halves it each round.

        Returns a dict with the tapes, the per-input branch variables, and the
        blind claims each curve's circuit will open on the other's commitments.
        """
        c1_padded, c2_padded = cls.ipa_rows(n_inputs, layers)
        c1_tape = VectorCommitmentTape(HeliosField, c1_padded)
        c2_tape = VectorCommitmentTape(SeleneField, c2_padded)

        per_input_vars, root_vars = cls._transcript_branches(branches, c1_tape, c2_tape)
        transcripted_inputs = cls._transcript_inputs(branches, c1_tape)
        c1_blind_claims, c2_blind_claims = cls._transcript_blinds(branches, c1_tape, c2_tape)

        return {
            "c1": c1_tape, "c2": c2_tape,
            "c1_padded": c1_padded, "c2_padded": c2_padded,
            "per_input_vars": per_input_vars,
            "root_vars": root_vars,
            "inputs": transcripted_inputs,
            "c1_blind_claims": c1_blind_claims,
            "c2_blind_claims": c2_blind_claims,
        }

    @staticmethod
    def _commit(params: FcmpParams, branches: BranchesWithBlinds, tapes, is_c1, rand_c1, rand_c2):
        """Form the Pedersen vector commitments over the tapes.

        Each tape commitment is masked by one blind. The branch blinds are not
        free: a branch commitment must come out equal to the tree node it stands for,
        which is why they are the negated branch-blind scalars: the circuit re-adds
        blind·H and lands exactly on hash_init + Σ childrenₓ·g. Slots past the
        branch blinds are masked randomly, and one of those random masks is the
        root blind, whose knowledge the Schnorr PoK below proves.
        """
        pvc_blinds_1 = [
            HeliosField(-b.inner.scalar.scalar % HeliosField.P) for b in branches.branches_1_blinds
        ]
        pvc_blinds_2 = [
            SeleneField(-b.inner.scalar.scalar % SeleneField.P) for b in branches.branches_2_blinds
        ]
        while len(pvc_blinds_1) < len(tapes["c1"].commitments):
            pvc_blinds_1.append(rand_c1())
        while len(pvc_blinds_2) < len(tapes["c2"].commitments):
            pvc_blinds_2.append(rand_c2())

        # The root's own commitment is the first one past the branch blinds.
        root_blind = (
            pvc_blinds_1[len(branches.branches_1_blinds)] if is_c1
            else pvc_blinds_2[len(branches.branches_2_blinds)]
        )

        g1, h1 = params.curve_1_generators.g_bold_slice(), params.curve_1_generators.h()
        g2, h2 = params.curve_2_generators.g_bold_slice(), params.curve_2_generators.h()

        return {
            "blinds_1": pvc_blinds_1,
            "blinds_2": pvc_blinds_2,
            "points_1": tapes["c1"].commit(g1, h1, pvc_blinds_1),
            "points_2": tapes["c2"].commit(g2, h2, pvc_blinds_2),
            "root_blind": root_blind,
            "h1": h1, "h2": h2,
        }

    @classmethod
    def _open_transcript(cls, branches, commitments, is_c1, root_bytes, rand_c1, rand_c2):
        """Fix the Fiat–Shamir context, and prove knowledge of the root blind.

        The context hash binds the statement (root, curve, and every input's blinded
        tuple) plus the Schnorr nonce, so nothing downstream can be chosen after
        seeing a challenge.

        The ordering constraint that matters: the Schnorr challenge is drawn
        after the vector commitments are written to the transcript. The PoK
        therefore covers them too, which is what stops a prover from picking a root
        blind to suit the commitments it already published.

        Returns (transcript, root_blind_pok).
        """
        rand = rand_c1 if is_c1 else rand_c2
        F = HeliosField if is_c1 else SeleneField
        h = commitments["h1"] if is_c1 else commitments["h2"]

        root_r = rand()                                   # Schnorr nonce
        root_blind_R = point_to_bytes(h * int(root_r))    # its commitment R = r·H

        input_tuples = [
            data.output_blinds.blind(data.output.O, data.output.I, data.output.C)
            for data in branches.per_input
        ]
        ctx = cls.transcript(is_c1, root_bytes, input_tuples, root_blind_R)
        transcript = ProverTranscript(ctx)

        # C1 then C2: two separate calls. The order is part of the wire format.
        commitments["raw_1"], _ = transcript.write_commitments(commitments["points_1"], [])
        commitments["raw_2"], _ = transcript.write_commitments(commitments["points_2"], [])

        c = transcript.challenge(F)
        s = F((int(root_r) + int(c) * int(commitments["root_blind"])) % F.P)
        return transcript, root_blind_R + s.to_bytes()

    @classmethod
    def _build_circuits(cls, params, branches, tapes, commitments, transcript):
        """Build the two R1CS systems, one per curve of the 2-cycle.

        Each input contributes a first_layer (open O, I, R, C from their published
        rerandomized forms and prove the leaf tuple is in the tree) plus one
        additional_layer per interior branch.

        The two circuits are interleaved because the tower is: a C1 layer's branch
        opens a *C2* commitment and vice versa, since a Selene point's x-coordinate
        lives in Helios's scalar field. The two iterators below carry each curve's
        commitment points and blinds across to the other curve's layers.
        """
        c1_pvc = [
            PedersenVectorCommitment(vals, b)
            for vals, b in zip(tapes["c1"].commitments, commitments["blinds_1"])
        ]
        c2_pvc = [
            PedersenVectorCommitment(vals, b)
            for vals, b in zip(tapes["c2"].commitments, commitments["blinds_2"])
        ]
        c1_circuit = Circuit.prove(HeliosField, c1_pvc)
        c2_circuit = Circuit.prove(SeleneField, c2_pvc)

        # One dlog challenge per curve, shared by every layer on it (mutable cells
        # because the first layer to need one creates it).
        c1_dlog_ch, c2_dlog_ch = [None], [None]

        c1_commit_iter = iter(zip(
            zip(commitments["raw_1"], commitments["blinds_1"]),  # (C1 point, C1 blind)
            tapes["c2_blind_claims"],                            # opened by C2 layers
        ))
        c2_commit_iter = iter(zip(
            zip(commitments["raw_2"], commitments["blinds_2"]),  # (C2 point, C2 blind)
            tapes["c1_blind_claims"],                            # opened by C1 layers
        ))

        for idx, (data, ti) in enumerate(zip(branches.per_input, tapes["inputs"])):
            c1_vars, c2_vars = tapes["per_input_vars"][idx]
            blinded = data.output_blinds.blind(data.output.O, data.output.I, data.output.C)
            cls._input(
                params,
                len(c1_vars) + len(c2_vars) + 1,   # this input's depth
                transcript,
                c1_circuit, c1_dlog_ch,
                c2_circuit, c2_dlog_ch,
                tapes["root_vars"], c1_vars, c2_vars,
                c2_commit_iter,   # C1 layers open C2 commitments
                c1_commit_iter,   # C2 layers open C1 commitments
                blinded, ti,
            )

        return {"c1": c1_circuit, "c2": c2_circuit}

    @staticmethod
    def _run_gbp(params, tapes, circuits, commitments, transcript, rand_c1, rand_c2):
        """Run the Generalized-Bulletproofs argument for each curve's R1CS.

        Both write into the same transcript, C1 first, so C2's challenges depend on
        C1's proof, and the pair cannot be mixed and matched across proofs.
        """
        c1_gens = params.curve_1_generators.reduce(tapes["c1_padded"])
        c2_gens = params.curve_2_generators.reduce(tapes["c2_padded"])

        c1_stmt, c1_witness = circuits["c1"].statement(c1_gens, commitments["raw_1"])
        c2_stmt, c2_witness = circuits["c2"].statement(c2_gens, commitments["raw_2"])

        c1_stmt.prove(rand_c1, transcript, c1_witness, HeliosField)
        c2_stmt.prove(rand_c2, transcript, c2_witness, SeleneField)

    # -- verify: reconstruction helpers -----------------------------------

    @staticmethod
    def _reconstruct_input_openings(c1_tape, n_inputs):
        """Reserve, per input, the tape slots the prover filled with its blind openings.

        Five claimed points (o_blind on T, i_blind on U and on V, i_blind_blind on T,
        c_blind on G), each a dlog decomposition, a divisor
        and the claimed point. The published O~/I~/R/C~ coordinates ride along in
        each claim's padding slots.

        i_blind_v reuses i_blind_u's dlog list object. That aliasing is the
        constraint forcing one i_blind scalar across both generators. If these were
        separate slots a prover could open the two to different scalars.
        """
        sb = OC_PARAMS.scalar_bits
        yx_c = OC_PARAMS.yx_coefficients
        x_c = OC_PARAMS.x_coefficients

        def claimed_point():
            return c1_tape.append_claimed_point(sb, yx_c, x_c, None, None, None, None)

        openings = []
        for _ in range(n_inputs):
            dv_o, dd_o, pt_o, O_vars = claimed_point()
            dv_u, dd_u, pt_u, I_vars = claimed_point()

            # i_blind on V: a divisor only: its dlog is i_blind_u's, below.
            iv_div, _extra = c1_tape.append_divisor(yx_c, x_c, None, None)

            dv_bb, dd_bb, pt_bb, i_blind_V_vars = claimed_point()
            dv_c, dd_c, pt_c, C_vars = claimed_point()

            i_blind_u_claim = PointWithDlog(
                dlog=dv_u, divisor=Divisor.from_tape_dict(dd_u), point=pt_u
            )
            openings.append({
                "O": (O_vars[0], O_vars[1]),
                "I": (I_vars[0], I_vars[1]),
                "C": (C_vars[0], C_vars[1]),
                "o_blind_claim": PointWithDlog(
                    dlog=dv_o, divisor=Divisor.from_tape_dict(dd_o), point=pt_o),
                "i_blind_u_claim": i_blind_u_claim,
                "i_blind_v_claim": PointWithDlog(
                    dlog=i_blind_u_claim.dlog,   # the shared object, see docstring
                    divisor=Divisor.from_tape_dict(iv_div),
                    point=(i_blind_V_vars[0], i_blind_V_vars[1])),
                "i_blind_blind_claim": PointWithDlog(
                    dlog=dv_bb, divisor=Divisor.from_tape_dict(dd_bb), point=pt_bb),
                "c_blind_claim": PointWithDlog(
                    dlog=dv_c, divisor=Divisor.from_tape_dict(dd_c), point=pt_c),
            })
        return openings

    @staticmethod
    def _reconstruct_blind_claims(c1_tape, c2_tape, n_inputs, is_c1, n_c1_branches, n_c2_branches):
        """Reserve the slots for each curve's branch-blind openings.

        They sit on the opposite curve's tape: a C1 layer opens a C2 commitment,
        so the C2 blinds' dlog claims live in the C1 tape and vice versa. The counts
        follow from the branch counts, plus one more on whichever curve carries the
        root (its blind is opened too, by the Schnorr PoK's counterpart in-circuit).
        """
        n_c1_claims = 0
        if n_c1_branches:
            # every C1 branch except each input's leaf branch, plus the root if on C1
            n_c1_claims = (n_c1_branches - n_inputs) + (n_inputs if is_c1 else 0)
        n_c2_claims = n_c2_branches + (0 if is_c1 else n_inputs)

        def claims(tape, params, count):
            out = []
            for _ in range(count):
                dv, ddiv, dpt, _pad = tape.append_claimed_point(
                    params.scalar_bits, params.yx_coefficients, params.x_coefficients,
                    None, None, None, None,
                )
                out.append(PointWithDlog(
                    dlog=dv, divisor=Divisor.from_tape_dict(ddiv), point=dpt))
            return out

        return (claims(c1_tape, C2_PARAMS, n_c1_claims),
                claims(c2_tape, C1_PARAMS, n_c2_claims))

    # Three phases, mirroring the prover:
    #
    #   1. RECONSTRUCT  rebuild the same tape layout and the same two R1CS systems
    #                   the prover built: from public data only, no witness
    #   2. REPLAY       re-open the Fiat–Shamir transcript over the published
    #                   commitments, re-deriving every challenge the prover used
    #   3. CHECK        queue the root-blind Schnorr PoK and both Generalized-
    #                   Bulletproofs arguments into the caller's batch verifiers
    #
    # The verifier never sees the constraint system. It derives it. That is what
    # makes the circuit consensus: prover and verifier must emit byte-identical rows
    # in identical order, or the challenges diverge and the proof fails.

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
        """Queue one FCMP++ membership proof for batch verification.

        proof          : the membership proof bytes (Fcmp.proof)
        root_blind_pok : the 64-byte Schnorr PoK (Fcmp.root_blind_pok)
        params         : protocol generators
        is_c1          : True if the tree root is on C1/Selene, False for C2/Helios
        tree_root_bytes: the 32-byte root the reference block commits to
        layers         : tree depth (>= 1)
        inputs         : per input, {'O_tilde','I_tilde','R','C_tilde'} as affine
                         (HeliosField, HeliosField) coordinate pairs
        verifier_1/2   : batch verifiers the caller creates and must finalize
        rng_fn         : callable() -> field element, the batch weights

        Raises on anything malformed. Returning does not mean the proof is valid,
        only that it was queued. Validity is the finalization's answer.
        """
        from itertools import repeat
        from mic.fcmp.curve import selene_from_bytes, helios_from_bytes

        n_inputs = len(inputs)
        c1_padded, c2_padded = cls.ipa_rows(n_inputs, layers)

        # -- 1. RECONSTRUCT ------------------------------------------------
        # Same tape layout as the prover's _arithmetize, with every value None:
        # only the shape matters here, because the shape is what names the wires.
        c1_tape = VectorCommitmentTape(HeliosField, c1_padded)
        c2_tape = VectorCommitmentTape(SeleneField, c2_padded)

        c1_branches_flat = []
        c2_branches_flat = []
        for _ in range(n_inputs):
            for i in range(layers - 1):
                if i % 2 == 0:
                    # layer 0 is the leaf branch: 38 outputs × 6 coordinates
                    blen = 6 * LAYER_ONE_LEN if i == 0 else LAYER_ONE_LEN
                    c1_branches_flat.append(c1_tape.append_branch(blen, None))
                else:
                    c2_branches_flat.append(c2_tape.append_branch(LAYER_TWO_LEN, None))

        root_is_c1 = (layers % 2) == 1
        if root_is_c1:
            root_len = 6 * LAYER_ONE_LEN if layers == 1 else LAYER_ONE_LEN
            root_vars = c1_tape.append_branch(root_len, None)
        else:
            root_vars = c2_tape.append_branch(LAYER_TWO_LEN, None)

        input_openings = cls._reconstruct_input_openings(c1_tape, n_inputs)
        c1_blind_claims, c2_blind_claims = cls._reconstruct_blind_claims(
            c1_tape, c2_tape, n_inputs, is_c1, len(c1_branches_flat), len(c2_branches_flat)
        )

        # -- 2. REPLAY -----------------------------------------------------
        # The same context the prover hashed, then the same commitment reads: so
        # every challenge below is re-derived, never taken from the proof.
        ctx = cls.transcript(is_c1, tree_root_bytes, inputs, root_blind_pok[:32])
        transcript = VerifierTranscript(ctx, proof)

        C1_pts, _ = transcript.read_commitments(len(c1_tape.commitments), 0, selene_from_bytes)
        C2_pts, _ = transcript.read_commitments(len(c2_tape.commitments), 0, helios_from_bytes)

        # -- 3. CHECK: the root-blind Schnorr PoK ---------------------------
        # The prover published a commitment to the root branch. This proves it knows
        # the blind relating that commitment to the actual on-chain root:
        #
        #     R + c·(claimed_root − actual_root) == s·H
        #
        # queued batch-weighted rather than checked outright. The challenge c comes
        # after the commitment reads, so the blind cannot be chosen to fit them.
        root_cidx = root_vars[0].commitment  # the commitment index, not a slot index
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

        # -- 3. CHECK: rebuild both circuits and queue the arguments --------
        # Identical structure to the prover's _build_circuits, witness-free.
        c1_circuit = Circuit.verify(HeliosField)
        c2_circuit = Circuit.verify(SeleneField)
        c1_dlog_ch = [None]
        c2_dlog_ch = [None]

        # Cross-curve, exactly as when proving: a C1 layer opens a C2 commitment.
        # No blinds here: the verifier has only the commitment points.
        c2_commit_iter = iter(
            zip(
                zip(C2_pts, repeat(None)),
                c1_blind_claims,
            )
        )
        c1_commit_iter = iter(
            zip(
                zip(C1_pts, repeat(None)),
                c2_blind_claims,
            )
        )

        # The flat branch lists were filled input-by-input, so slice them back apart.
        c1_per_inp = layers // 2
        c2_per_inp = (layers - 1) // 2

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

        # Queue both arguments. C1 first: its proof is in the transcript C2's
        # challenges are drawn from, so the two cannot be recombined across proofs.
        c1_gens = params.curve_1_generators.reduce(c1_padded)
        c2_gens = params.curve_2_generators.reduce(c2_padded)

        # Each curve's batch weights must land in its scalar field:
        # C1 = Selene, whose scalar field is HeliosField. C2 = Helios, SeleneField.
        def _rng_c1():
            return HeliosField(int(rng_fn()))

        def _rng_c2():
            return SeleneField(int(rng_fn()))

        c1_stmt, _ = c1_circuit.statement(c1_gens, C1_pts)
        c1_stmt.verify(_rng_c1, verifier_1, transcript, HeliosField, selene_from_bytes)

        c2_stmt, _ = c2_circuit.statement(c2_gens, C2_pts)
        c2_stmt.verify(_rng_c2, verifier_2, transcript, SeleneField, helios_from_bytes)

        # Every byte of the proof must have been consumed. Trailing bytes would be
        # a malleability vector: two distinct blobs verifying as the same proof.
        if not transcript.is_exhausted():
            raise ValueError(
                f"proof has {len(transcript._proof) - transcript._pos} trailing bytes: "
                "possible proof malleability or parsing error"
            )
