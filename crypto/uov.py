"""
UOV-Based Multivariate Post-Quantum Encryption over GF(256)
============================================================
Implements an Unbalanced Oil and Vinegar (UOV) cipher over GF(256).

Scheme (no input-mixing layer S; only output mixer T):
  Private key:  central-map coefficients (A,B,C,D,E) + T_inv
  Public key:   P(z) = T·F(z) expressed as quad/lin/const coefficient tables.

Encryption (per block of OIL bytes):
  1. Treat plaintext block as x_oil in GF(256)^OIL
  2. Choose random x_vin in GF(256)^VIN
  3. y = P(x_vin || x_oil)   -- OIL bytes
  4. Ciphertext block = y || x_vin   -- OIL + VIN bytes

Decryption (per ciphertext block):
  1. Split: y = block[:OIL], x_vin = block[OIL:]
  2. y' = T_inv · y  =>  y'_k = F_k(x_vin, x_oil)
  3. Substitute known x_vin  =>  linear system M·x_oil = rhs
  4. Gauss-eliminate over GF(256)  =>  x_oil = plaintext block
"""

import os
import json
import base64
from .gf256 import mul, inv as gf_inv, mat_inv, mat_vec_mul, random_invertible_matrix, gauss_solve

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
VIN = 12   # number of vinegar variables
OIL = 8    # number of oil variables (= equations = plaintext block size in bytes)
N   = VIN + OIL


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _random_symmetric_matrix(size, rng):
    M = [[0] * size for _ in range(size)]
    for i in range(size):
        for j in range(i, size):
            v = int(rng.integers(1, 256))
            M[i][j] = v
            M[j][i] = v
    return M


def _central_eval(A, B, C_coeff, D, E, xv, xo):
    """Evaluate all OIL central polynomials. Returns list of OIL GF(256) values."""
    result = []
    for k in range(OIL):
        val = E[k]
        for i in range(VIN):
            for j in range(VIN):
                val ^= mul(A[k][i][j], mul(xv[i], xv[j]))
            for j in range(OIL):
                val ^= mul(B[k][i][j], mul(xv[i], xo[j]))
            val ^= mul(C_coeff[k][i], xv[i])
        for j in range(OIL):
            val ^= mul(D[k][j], xo[j])
        result.append(val)
    return result


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def generate_keypair(seed: bytes | None = None):
    """Generate a UOV public/private key pair."""
    import numpy as np
    rng = np.random.default_rng(
        np.frombuffer(seed, dtype=np.uint8) if seed else None
    )

    # Central map (private)
    A = [_random_symmetric_matrix(VIN, rng) for _ in range(OIL)]
    B = [[list(map(int, rng.integers(0, 256, OIL))) for _ in range(VIN)] for _ in range(OIL)]
    C = [list(map(int, rng.integers(0, 256, VIN))) for _ in range(OIL)]
    D = [list(map(int, rng.integers(0, 256, OIL))) for _ in range(OIL)]
    E = list(map(int, rng.integers(0, 256, OIL)))

    # Output mixer (private)
    T     = random_invertible_matrix(OIL, rng)
    T_inv = mat_inv(T)

    # ── Extract public key coefficients ───────────────────────────────────
    # Public polynomial: P_k(z) = sum_{i<=j} Q[k][i][j]*z_i*z_j + sum_i L[k][i]*z_i + Const[k]
    #
    # Coefficient extraction via finite differences on F(z) = central_eval(z[:VIN], z[VIN:]):
    #   Cross (i<j):  Q[k][i][j] = F(e_i+e_j)[k] ^ F(e_i)[k] ^ F(e_j)[k] ^ F(0)[k]
    #   Diagonal + linear separation using F(2*e_i):
    #     delta1 = F(e_i)[k] ^ F(0)[k]   = Q[k][i][i] + L[k][i]        (c=1)
    #     delta2 = F(2*e_i)[k] ^ F(0)[k] = 4*Q[k][i][i] + 2*L[k][i]   (c=2)
    #     delta2 ^ 2*delta1 = 6*Q[k][i][i]
    #     => Q[k][i][i] = (delta2 ^ mul(2,delta1)) * inv(6)
    #        L[k][i] = delta1 ^ Q[k][i][i]
    #
    # Then apply T:  pub_quad[k] = sum_l T[k][l] * Q_raw[l]

    basis = [[1 if r == c else 0 for c in range(N)] for r in range(N)]
    zeros = [0] * N

    def _F(z):
        return _central_eval(A, B, C, D, E, z[:VIN], z[VIN:])

    f0   = _F(zeros)
    f_ei = [_F(basis[i]) for i in range(N)]

    two_ei_vecs = [[0] * N for _ in range(N)]
    for i in range(N):
        two_ei_vecs[i][i] = 2
    f_2ei = [_F(two_ei_vecs[i]) for i in range(N)]

    inv6 = gf_inv(6)

    Q_raw = [[[0] * N for _ in range(N)] for _ in range(OIL)]
    L_raw = [[0] * N for _ in range(OIL)]

    for i in range(N):
        for k in range(OIL):
            d1 = f_ei[i][k] ^ f0[k]
            d2 = f_2ei[i][k] ^ f0[k]
            q  = mul(d2 ^ mul(2, d1), inv6)
            Q_raw[k][i][i] = q
            L_raw[k][i]    = d1 ^ q

    for i in range(N):
        for j in range(i + 1, N):
            eiej = [basis[i][r] ^ basis[j][r] for r in range(N)]
            fij  = _F(eiej)
            for k in range(OIL):
                Q_raw[k][i][j] = fij[k] ^ f_ei[i][k] ^ f_ei[j][k] ^ f0[k]

    # Apply T on output
    pub_quad  = [[[0] * N for _ in range(N)] for _ in range(OIL)]
    pub_lin   = [[0] * N for _ in range(OIL)]
    pub_const = mat_vec_mul(T, f0)

    for i in range(N):
        for j in range(i, N):      # upper-triangular (i <= j)
            q_vec = [Q_raw[l][i][j] for l in range(OIL)]
            mixed = mat_vec_mul(T, q_vec)
            for k in range(OIL):
                pub_quad[k][i][j] = mixed[k]

    for i in range(N):
        l_vec = [L_raw[l][i] for l in range(OIL)]
        mixed = mat_vec_mul(T, l_vec)
        for k in range(OIL):
            pub_lin[k][i] = mixed[k]

    public_key  = {"quad": pub_quad, "lin": pub_lin, "const": pub_const}
    private_key = {"A": A, "B": B, "C": C, "D": D, "E": E, "T_inv": T_inv}
    return public_key, private_key


# ---------------------------------------------------------------------------
# Block-level encrypt / decrypt
# ---------------------------------------------------------------------------

def _eval_public(pk, z):
    """Evaluate P(z) using upper-triangular Q table (diagonal + cross terms)."""
    Q, Lin, Const = pk["quad"], pk["lin"], pk["const"]
    result = list(Const)
    for k in range(OIL):
        for i in range(N):
            result[k] ^= mul(Lin[k][i], z[i])
            result[k] ^= mul(Q[k][i][i], mul(z[i], z[i]))  # diagonal z_i^2
            for j in range(i + 1, N):
                result[k] ^= mul(Q[k][i][j], mul(z[i], z[j]))  # cross z_i*z_j
    return result


def _encrypt_block(pk, plaintext_block: bytes) -> bytes:
    assert len(plaintext_block) == OIL
    x_oil = list(plaintext_block)
    x_vin = list(os.urandom(VIN))
    y     = _eval_public(pk, x_vin + x_oil)
    return bytes(y) + bytes(x_vin)


def _decrypt_block(sk, cipher_block: bytes) -> bytes:
    assert len(cipher_block) == OIL + VIN
    y, x_vin  = list(cipher_block[:OIL]), list(cipher_block[OIL:])
    T_inv     = sk["T_inv"]
    A, B, C, D, E = sk["A"], sk["B"], sk["C"], sk["D"], sk["E"]

    y_prime = mat_vec_mul(T_inv, y)

    M   = [[0] * OIL for _ in range(OIL)]
    rhs = list(y_prime)

    for k in range(OIL):
        # Vinegar contribution (constant in x_oil)
        vc = E[k]
        for i in range(VIN):
            for j in range(VIN):
                vc ^= mul(A[k][i][j], mul(x_vin[i], x_vin[j]))
            vc ^= mul(C[k][i], x_vin[i])
        rhs[k] ^= vc

        # Coefficient of x_oil[j]
        for j in range(OIL):
            coeff = D[k][j]
            for i in range(VIN):
                coeff ^= mul(B[k][i][j], x_vin[i])
            M[k][j] = coeff

    return bytes(gauss_solve(M, rhs))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, public_key: dict) -> bytes:
    """UOV encrypt with PKCS#7 padding."""
    pad_len = OIL - (len(plaintext) % OIL)
    padded  = plaintext + bytes([pad_len] * pad_len)
    ct = b""
    for i in range(0, len(padded), OIL):
        ct += _encrypt_block(public_key, padded[i:i + OIL])
    return ct


def decrypt(ciphertext: bytes, private_key: dict) -> bytes:
    """UOV decrypt, removes PKCS#7 padding."""
    bs = OIL + VIN
    if len(ciphertext) % bs != 0:
        raise ValueError("Ciphertext length not a multiple of block size")
    pt = b""
    for i in range(0, len(ciphertext), bs):
        pt += _decrypt_block(private_key, ciphertext[i:i + bs])
    pad_len = pt[-1]
    if pad_len == 0 or pad_len > OIL:
        raise ValueError("Invalid padding")
    return pt[:-pad_len]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def serialize_key(key: dict) -> str:
    return base64.b64encode(json.dumps(key).encode()).decode()


def deserialize_key(s: str) -> dict:
    return json.loads(base64.b64decode(s.encode()).decode())


def encrypt_to_b64(plaintext: bytes, public_key: dict) -> str:
    return base64.b64encode(encrypt(plaintext, public_key)).decode()


def decrypt_from_b64(b64_cipher: str, private_key: dict) -> bytes:
    return decrypt(base64.b64decode(b64_cipher.encode()), private_key)
