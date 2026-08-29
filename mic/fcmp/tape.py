"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

VectorCommitmentTape.

Packs witness scalars into groups of COMMITMENT_WORD_LEN for the Pedersen vector
commitments.  
"""

from mic.fcmp.multiexp import multiexp
from mic.fcmp.curve import WPoint

COMMITMENT_WORD_LEN = 128

# A variable reference: which commitment slot and which index within it.
class Variable:
    __slots__ = ("commitment", "index")

    def __init__(self, commitment: int, index: int):
        self.commitment = commitment
        self.index = index

    def __repr__(self):
        return f"Variable(c={self.commitment}, j={self.index})"


class VectorCommitmentTape:
    """The witness tape.

    field_cls  : HeliosField | SeleneField (the scalar field)
    commitment_len : total scalars per commitment (multiple of COMMITMENT_WORD_LEN)
    """

    def __init__(self, field_cls, commitment_len: int):
        if commitment_len % COMMITMENT_WORD_LEN != 0:
            raise ValueError(
                f"commitment_len {commitment_len} must be divisible by {COMMITMENT_WORD_LEN}"
            )
        self.field_cls = field_cls
        self.commitment_len = commitment_len
        self.current_j_offset = 0
        self.commitments: list[list] = []  # list of lists of field elements
        self.branch_lengths: list[int] = []

    # ------------------------------------------------------------------
    # Internal: append one 128-word chunk
    # ------------------------------------------------------------------

    def append(self, variables=None) -> list:
        """Append a 128-scalar chunk. variables=None means verifier mode (no witness)."""
        if variables is not None:
            if len(variables) != COMMITMENT_WORD_LEN:
                raise ValueError(f"expected {COMMITMENT_WORD_LEN} variables, got {len(variables)}")

        vals = variables if variables is not None else []

        if self.current_j_offset == 0:
            self.commitments.append(vals)
        else:
            self.commitments[-1].extend(vals)

        i = len(self.commitments) - 1
        j_range = range(self.current_j_offset, self.current_j_offset + COMMITMENT_WORD_LEN)
        res = [Variable(i, j) for j in j_range]

        self.current_j_offset += COMMITMENT_WORD_LEN
        if self.current_j_offset == self.commitment_len:
            self.current_j_offset = 0

        return res


    def append_branch(self, branch_len: int, branch=None) -> list:
        if self.current_j_offset != 0:
            raise ValueError(
                "append_branch must be called at a commitment boundary (current_j_offset != 0)"
            )
        if len(self.branch_lengths) != len(self.commitments):
            raise ValueError("branch_lengths/commitments length mismatch")
        self.branch_lengths.append(branch_len)
        if branch_len <= 0:
            raise ValueError(f"branch_len must be positive, got {branch_len}")
        if branch_len > self.commitment_len:
            raise ValueError(
                f"branch_len {branch_len} exceeds commitment_len {self.commitment_len}"
            )

        words = (branch_len + COMMITMENT_WORD_LEN - 1) // COMMITMENT_WORD_LEN

        empty = None
        if branch is not None:
            empty = [self.field_cls(0)] * COMMITMENT_WORD_LEN

        # Pad branch to multiple of COMMITMENT_WORD_LEN
        padded = None
        if branch is not None:
            if len(branch) != branch_len:
                raise ValueError(f"branch length {len(branch)} != branch_len {branch_len}")
            padded = list(branch)
            while len(padded) % COMMITMENT_WORD_LEN != 0:
                padded.append(self.field_cls(0))

        branch_variables = []
        for b in range(words):
            chunk = None
            if padded is not None:
                chunk = padded[b * COMMITMENT_WORD_LEN : (b + 1) * COMMITMENT_WORD_LEN]
            branch_variables.extend(self.append(chunk))

        # Truncate padding variables
        branch_variables = branch_variables[:branch_len]

        # Pad remaining commitment slots
        total_words = self.commitment_len // COMMITMENT_WORD_LEN
        for _ in range(words, total_words):
            self.append(empty)

        return branch_variables


    def append_dlog(self, scalar_bits: int, dlog=None, padding=None, extra=None):
        """Append a dlog (scalar_bits ≤ 255 bits) + optional padding + extra.

        Returns (dlog_vars[scalar_bits], padding_vars, extra_var).
        """
        if scalar_bits > 255:
            raise ValueError(f"scalar_bits {scalar_bits} exceeds maximum of 255")

        witness_a = None
        witness_b = None

        if dlog is not None:
            if len(dlog) != scalar_bits:
                raise ValueError(f"dlog length {len(dlog)} != scalar_bits {scalar_bits}")
            w = []
            for bit in dlog:
                w.append(self.field_cls(int(bit)))

            pad = padding if padding is not None else []
            free = 255 - scalar_bits
            if len(pad) > free:
                raise ValueError(f"padding length {len(pad)} exceeds free slots {free}")
            for i in range(free):
                w.append(pad[i] if i < len(pad) else self.field_cls(0))
            if len(w) != 255:
                raise ValueError(f"dlog witness vector length {len(w)} != 255")
            w.append(extra)
            if len(w) != 2 * COMMITMENT_WORD_LEN:
                raise ValueError(
                    f"dlog witness vector length {len(w)} != {2 * COMMITMENT_WORD_LEN}"
                )

            witness_a = w[:COMMITMENT_WORD_LEN]
            witness_b = w[COMMITMENT_WORD_LEN:]

        variables = self.append(witness_a) + self.append(witness_b)

        extra_var = variables.pop()
        padding_vars = variables[scalar_bits:255]
        dlog_vars = variables[:scalar_bits]

        return dlog_vars, padding_vars, extra_var


    def append_divisor(self, yx_count: int, x_count: int, divisor=None, extra=None):
        """Append a divisor polynomial to the tape.

        yx_count : number of yx coefficients (Parameters::YxCoefficients)
        x_count  : number of x coefficients (Parameters::XCoefficients)

        divisor dict (if not None):
          { 'y': y_coeff, 'yx': [yx0, yx1, ...], 'x': [x0, x1, ...], 'zero': zero_coeff }
          x[0] must equal 1 (normalized leading coefficient, not stored).

        Returns (Divisor, extra_var) where Divisor is a dict of Variable references.
        """
        witness_a = None
        witness_b = None

        if divisor is not None:
            w = []
            # y: 1 slot
            w.append(divisor.get("y", self.field_cls(0)))

            # yx: yx_count slots
            yx = divisor.get("yx", [])
            if len(yx) > yx_count:
                raise ValueError(f"yx coefficients {len(yx)} exceed yx_count {yx_count}")
            for i in range(yx_count):
                w.append(yx[i] if i < len(yx) else self.field_cls(0))

            # x: x_count-1 slots (skip x[0]=1 which is normalized)
            x = divisor.get("x", [])
            if len(x) > x_count:
                raise ValueError(f"x coefficients {len(x)} exceed x_count {x_count}")
            # x[0] should be 1 (normalized). Skip it, store x[1..x_count-1]
            for i in range(1, x_count):
                w.append(x[i] if i < len(x) else self.field_cls(0))

            # zero: 1 slot
            w.append(divisor.get("zero", self.field_cls(0)))

            if len(w) > 255:
                raise ValueError(f"divisor witness vector length {len(w)} exceeds 255")
            while len(w) < 255:
                w.append(self.field_cls(0))

            w.append(extra)
            if len(w) != 2 * COMMITMENT_WORD_LEN:
                raise ValueError(
                    f"divisor witness vector length {len(w)} != {2 * COMMITMENT_WORD_LEN}"
                )

            witness_a = w[:COMMITMENT_WORD_LEN]
            witness_b = w[COMMITMENT_WORD_LEN:]

        variables = self.append(witness_a) + self.append(witness_b)

        extra_var = variables.pop()

        cursor = 1
        yx_vars = variables[cursor : cursor + yx_count]
        cursor += yx_count
        x_from_power2 = variables[cursor : cursor + (x_count - 1)]
        cursor += x_count - 1
        zero_var = variables[cursor]

        divisor_struct = {
            "y": variables[0],
            "yx": yx_vars,
            "x_from_power_of_2": x_from_power2,
            "zero": zero_var,
        }

        return divisor_struct, extra_var


    def append_claimed_point(
        self,
        scalar_bits: int,
        yx_count: int,
        x_count: int,
        dlog=None,
        divisor=None,
        point=None,
        padding=None,
    ):
        """Append a full PointWithDlog to the tape.

        Uses 4 chunks (512 slots):
          Chunks 1–2 (append_dlog):
            [0..scalar_bits)   : dlog bit variables
            [scalar_bits..255) : padding variables (e.g. O.x, O.y)
            [255]              : extra = point.x

          Chunks 3–4 (append_divisor):
            divisor layout, [255] = point.y

        Returns (dlog_vars, divisor_vars_dict, point_xy, padding_vars) where:
          - dlog_vars        : list of Variable [scalar_bits]
          - divisor_vars_dict: {"y", "yx", "x_from_power_of_2", "zero"} of Variable
          - point_xy         : (x_var, y_var), the extra slots from each half
          - padding_vars     : list of Variable in [scalar_bits..255)
        """
        # Build witness values
        point_x = point[0] if point is not None else None
        point_y = point[1] if point is not None else None

        dlog_vars, pad_vars, x_var = self.append_dlog(scalar_bits, dlog, padding, extra=point_x)
        div_dict, y_var = self.append_divisor(yx_count, x_count, divisor, extra=point_y)

        return dlog_vars, div_dict, (x_var, y_var), pad_vars


    def commit(self, g_bold: list, h, blinds: list) -> list:
        """Compute commitment points for all slots.

        g_bold : list of WPoints (generators G_bold)
        h      : WPoint (blinding generator H)
        blinds : list of field elements, one per commitment slot

        Returns list of WPoints.
        """
        if len(self.commitments) != len(blinds):
            raise ValueError(
                f"commitments/blinds length mismatch: {len(self.commitments)} vs {len(blinds)}"
            )
        identity = WPoint.identity(h.field_cls, h.B)
        results = []

        for i, (values, blind) in enumerate(zip(self.commitments, blinds)):
            # Branch commitments only use branch_len scalars. Others use all.
            if i < len(self.branch_lengths):
                n = self.branch_lengths[i]
            else:
                n = len(values)

            pairs = []
            for j in range(n):
                pairs.append((values[j], g_bold[j]))
            pairs.append((blind, h))

            pt = multiexp(pairs, identity)
            results.append(pt)

        return results
