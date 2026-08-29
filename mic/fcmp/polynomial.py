"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Acknowledgments: incorporates monero-oxide
(https://github.com/monero-oxide/monero-oxide), licensed under the MIT License.

Bivariate polynomial arithmetic over a prime field.

Structure: zero + sum(y_i * y^(i+1)) + sum(yx_ij * y^(i+1) * x^(j+1)) + sum(x_i * x^(i+1))
"""

class Poly:
    """
    Bivariate polynomial.

    y[i]     → coefficient of y^(i+1)
    yx[i][j] → coefficient of y^(i+1) * x^(j+1)
    x[i]     → coefficient of x^(i+1)
    zero     → constant term
    """

    __slots__ = ("zero", "y", "yx", "x")

    def __init__(self, zero, y=None, yx=None, x=None):
        self.zero = zero
        self.y = list(y) if y is not None else []
        self.yx = [list(r) for r in yx] if yx is not None else []
        self.x = list(x) if x is not None else []

    def _zero(self):
        """Return a zero field element of the same type as self.zero."""
        return self.zero * 0

    def eval(self, x_val, y_val):
        res = self.zero
        for i, c in enumerate(self.y):
            res = res + y_val ** (i + 1) * c
        for i, row in enumerate(self.yx):
            yp = y_val ** (i + 1)
            for j, c in enumerate(row):
                res = res + yp * x_val ** (j + 1) * c
        for i, c in enumerate(self.x):
            res = res + x_val ** (i + 1) * c
        return res

    def __neg__(self):
        return Poly(
            -self.zero,
            [-c for c in self.y],
            [[-c for c in row] for row in self.yx],
            [-c for c in self.x],
        )

    def __add__(self, other):
        res_zero = self.zero + other.zero
        res_y = list(self.y)
        res_yx = [list(r) for r in self.yx]
        res_x = list(self.x)

        z = self._zero()

        while len(res_y) < len(other.y):
            res_y.append(z)
        for i, c in enumerate(other.y):
            res_y[i] = res_y[i] + c

        while len(res_yx) < len(other.yx):
            res_yx.append([])
        for i, row in enumerate(other.yx):
            while len(res_yx[i]) < len(row):
                res_yx[i].append(z)
            for j, c in enumerate(row):
                res_yx[i][j] = res_yx[i][j] + c

        while len(res_x) < len(other.x):
            res_x.append(z)
        for i, c in enumerate(other.x):
            res_x[i] = res_x[i] + c

        return Poly(res_zero, res_y, res_yx, res_x)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, other):
        if isinstance(other, Poly):
            return self._poly_mul(other)
        s = other
        return Poly(
            self.zero * s,
            [c * s for c in self.y],
            [[c * s for c in row] for row in self.yx],
            [c * s for c in self.x],
        )

    def __rmul__(self, other):
        return self.__mul__(other)

    def _shift_by_x(self, power):
        """Multiply by x^power."""
        if power == 0:
            return Poly(self.zero, self.y, self.yx, self.x)
        res = Poly(self.zero, self.y, self.yx, self.x)
        z = self._zero()
        for _ in range(power):
            res.x.insert(0, z)
            new_yx = []
            for row in res.yx:
                new_row = list(row)
                new_row.insert(0, z)
                new_yx.append(new_row)
            res.yx = new_yx

        # Move the zero coefficient into x (now at position power-1)
        res.x[power - 1] = res.zero
        res.zero = z

        # Move y coefficients into yx
        while len(res.yx) < len(res.y):
            row = [z] * power
            res.yx.append(row)
        for i in range(len(res.y)):
            while len(res.yx[i]) < power:
                res.yx[i].insert(0, z)
            res.yx[i][power - 1] = res.y[i]
        res.y = []

        return res

    def _shift_by_y(self, power):
        """Multiply by y^power."""
        if power == 0:
            return Poly(self.zero, self.y, self.yx, self.x)
        z = self._zero()
        new_y = [z] * power + list(self.y)
        new_yx = [[]] * power + [list(r) for r in self.yx]

        # Move zero_coefficient into y
        new_y[power - 1] = self.zero

        # Move x_coefficients into yx at y-power-1
        if self.x:
            new_yx[power - 1] = list(self.x)

        return Poly(z, new_y, new_yx, [])

    def _poly_mul(self, other):
        res = self * other.zero

        # y-terms in other
        for i, c in enumerate(other.y):
            scaled = self * c
            res = res + scaled._shift_by_y(i + 1)

        # yx-terms in other
        for i, row in enumerate(other.yx):
            for j, c in enumerate(row):
                scaled = self * c
                res = res + scaled._shift_by_y(i + 1)._shift_by_x(j + 1)

        # x-terms in other
        for i, c in enumerate(other.x):
            scaled = self * c
            res = res + scaled._shift_by_x(i + 1)

        return res


    def normalize_x_coefficient(self):
        """Divide all coefficients by x_coefficients[0] so it becomes 1."""
        inv = self.x[0].inv()
        return self * inv


    def __repr__(self):
        return f"Poly(zero={self.zero}, " f"y={self.y}, yx={self.yx}, x={self.x})"
