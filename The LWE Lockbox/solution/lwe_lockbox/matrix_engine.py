"""Matrix generation and rank checks over Z_q."""

from __future__ import annotations

import random
from typing import List, Tuple

from .obfuscation import derive_matrix_seed
from .params import M, N, Q

Matrix = List[List[int]]


def generate_matrix(seed: int, m: int = M, n: int = N, q: int = Q) -> Matrix:
    rng = random.Random(seed)
    return [[rng.randrange(q) for _ in range(n)] for _ in range(m)]


def rank_mod_q(matrix: Matrix, q: int = Q) -> int:
    if not matrix:
        return 0

    rows = [row[:] for row in matrix]
    m = len(rows)
    n = len(rows[0])
    rank = 0
    pivot_row = 0

    for col in range(n):
        if pivot_row >= m:
            break

        pivot = None
        for row in range(pivot_row, m):
            if rows[row][col] % q != 0:
                pivot = row
                break

        if pivot is None:
            continue

        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]

        pivot_val = rows[pivot_row][col] % q
        inv = pow(pivot_val, q - 2, q)
        rows[pivot_row] = [(x * inv) % q for x in rows[pivot_row]]

        for row in range(m):
            if row == pivot_row:
                continue
            factor = rows[row][col] % q
            if factor == 0:
                continue
            rows[row] = [
                (rows[row][c] - factor * rows[pivot_row][c]) % q for c in range(n)
            ]

        pivot_row += 1
        rank += 1

    return rank


def generate_full_rank_matrix(
    m: int = M,
    n: int = N,
    q: int = Q,
    max_attempts: int = 256,
) -> Tuple[Matrix, int, int]:
    for counter in range(max_attempts):
        seed = derive_matrix_seed(counter)
        matrix = generate_matrix(seed=seed, m=m, n=n, q=q)
        rank = rank_mod_q(matrix, q=q)
        if rank == n:
            return matrix, seed, counter

    raise RuntimeError("unable to produce full-rank matrix within max_attempts")
