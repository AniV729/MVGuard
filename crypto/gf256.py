"""
GF(256) Arithmetic Module
=========================
Implements arithmetic in GF(2^8) using the AES irreducible polynomial:
    p(x) = x^8 + x^4 + x^3 + x + 1  (0x11b)

Operations:
- Addition / Subtraction (XOR in characteristic 2)
- Multiplication via Zech logarithm lookup tables
- Multiplicative inverse via Fermat's little theorem (a^254)
- Matrix operations (for UOV key generation and decryption)
"""

import numpy as np

# ---------------------------------------------------------------------------
# Precompute exp/log tables for fast multiplication
# ---------------------------------------------------------------------------
# Irreducible polynomial for GF(2^8):  x^8 + x^4 + x^3 + x + 1  (AES / 0x11b)
_POLY = 0x11b

_EXP = [0] * 512
_LOG = [0] * 256


def _xtime(a: int) -> int:
    """Multiply by x (≡ 2) in GF(2^8): left-shift then reduce."""
    a = (a << 1) & 0x1FF
    if a & 0x100:
        a ^= _POLY
    return a & 0xFF


def _build_tables():
    """
    Build exp/log tables using the primitive element g = 3 (= x+1 in GF(2^8)).
    The element 2 has order 51 with the AES polynomial, so it is NOT primitive.
    The element 3 = x+1  has multiplicative order 255 and generates all of GF(256)*.
    """
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # Multiply by 3 = (x+1): g^{i+1} = _xtime(x) XOR x
        x = _xtime(x) ^ x
    # Duplicate entries for convenient wrap-around in mul()
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def add(a: int, b: int) -> int:
    """Add two GF(256) elements (XOR)."""
    return a ^ b

sub = add  # subtraction == addition in GF(2^8)


def mul(a: int, b: int) -> int:
    """Multiply two GF(256) elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def inv(a: int) -> int:
    """Multiplicative inverse in GF(256)."""
    if a == 0:
        raise ZeroDivisionError("Zero has no inverse in GF(256)")
    return _EXP[255 - _LOG[a]]


def div(a: int, b: int) -> int:
    """Divide a by b in GF(256)."""
    return mul(a, inv(b))


# ---------------------------------------------------------------------------
# Matrix operations over GF(256)
# All matrices are represented as Python lists-of-lists of ints in [0,255].
# ---------------------------------------------------------------------------

def mat_mul(A, B):
    """Matrix multiply A (m×k) × B (k×n) over GF(256)."""
    m, k = len(A), len(A[0])
    k2, n = len(B), len(B[0])
    assert k == k2, "Incompatible matrix dimensions"
    C = [[0] * n for _ in range(m)]
    for i in range(m):
        for j in range(n):
            acc = 0
            for l in range(k):
                acc ^= mul(A[i][l], B[l][j])
            C[i][j] = acc
    return C


def mat_vec_mul(A, v):
    """Multiply matrix A (m×n) by column vector v (n,) over GF(256)."""
    m, n = len(A), len(A[0])
    assert len(v) == n, "Incompatible dimensions"
    result = [0] * m
    for i in range(m):
        acc = 0
        for j in range(n):
            acc ^= mul(A[i][j], v[j])
        result[i] = acc
    return result


def mat_inv(A):
    """
    Compute the inverse of square matrix A over GF(256) via
    Gauss-Jordan elimination.  Raises ValueError if singular.
    """
    n = len(A)
    # Build augmented matrix [A | I]
    aug = [row[:] + ([1 if j == i else 0 for j in range(n)]) for i, row in enumerate(A)]

    for col in range(n):
        # Find pivot
        pivot = None
        for row in range(col, n):
            if aug[row][col] != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is singular — cannot invert")
        aug[col], aug[pivot] = aug[pivot], aug[col]

        # Scale pivot row so that aug[col][col] == 1
        scale = inv(aug[col][col])
        aug[col] = [mul(x, scale) for x in aug[col]]

        # Eliminate column in all other rows
        for row in range(n):
            if row != col and aug[row][col] != 0:
                factor = aug[row][col]
                aug[row] = [aug[row][j] ^ mul(factor, aug[col][j]) for j in range(2 * n)]

    # Extract right half
    return [row[n:] for row in aug]


def random_invertible_matrix(n: int, rng=None) -> list:
    """
    Generate a random invertible n×n matrix over GF(256).
    Uses rejection sampling — succeeds almost certainly on first try.
    """
    if rng is None:
        rng = np.random.default_rng()

    for _ in range(200):
        M = [[int(rng.integers(0, 256)) for _ in range(n)] for _ in range(n)]
        try:
            mat_inv(M)
            return M
        except ValueError:
            pass
    raise RuntimeError("Could not generate invertible matrix after 200 attempts")


def gauss_solve(A, b):
    """
    Solve linear system A·x = b over GF(256) via Gaussian elimination.
    A is m×n, b is length-m.
    Returns (x, True) if unique solution exists, or raises ValueError.
    """
    m = len(A)
    n = len(A[0])
    # Augmented matrix
    aug = [A[i][:] + [b[i]] for i in range(m)]

    pivot_cols = []
    row = 0
    for col in range(n):
        # Find pivot in this column
        pivot = None
        for r in range(row, m):
            if aug[r][col] != 0:
                pivot = r
                break
        if pivot is None:
            continue
        aug[row], aug[pivot] = aug[pivot], aug[row]
        pivot_cols.append(col)

        scale = inv(aug[row][col])
        aug[row] = [mul(x, scale) for x in aug[row]]

        for r in range(m):
            if r != row and aug[r][col] != 0:
                factor = aug[r][col]
                aug[r] = [aug[r][j] ^ mul(factor, aug[row][j]) for j in range(n + 1)]
        row += 1

    # Check consistency
    for r in range(row, m):
        if aug[r][-1] != 0:
            raise ValueError("Inconsistent system — no solution")

    # Back-substitute
    x = [0] * n
    for i, col in enumerate(pivot_cols):
        x[col] = aug[i][-1]
    return x
