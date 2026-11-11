"""Secret-vector encoding and locked-vector construction."""

from __future__ import annotations

from typing import Iterable, List

from .params import N, Q, TRUE_FLAG


def encode_flag_to_secret(flag: str = TRUE_FLAG, n: int = N) -> List[int]:
    payload = flag.encode("ascii")
    if len(payload) > n:
        raise ValueError(f"flag length {len(payload)} exceeds secret dimension {n}")

    pad_len = n - len(payload)
    if pad_len <= 0:
        raise ValueError("padding length must be positive")

    padded = payload + bytes([pad_len]) * pad_len
    return list(padded)


def decode_secret_to_flag(secret: Iterable[int]) -> str:
    data = bytes(int(x) & 0xFF for x in secret)
    if not data:
        raise ValueError("secret vector is empty")

    pad_len = data[-1]
    if pad_len <= 0 or pad_len > len(data):
        raise ValueError("invalid padding in recovered secret")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("padding bytes are inconsistent")

    return data[:-pad_len].decode("ascii")


def compute_locked_vector(
    matrix: List[List[int]],
    secret: List[int],
    error: List[int],
    q: int = Q,
) -> List[int]:
    if len(matrix) != len(error):
        raise ValueError("matrix row count must equal error length")
    if not matrix or len(matrix[0]) != len(secret):
        raise ValueError("matrix column count must equal secret length")

    out: List[int] = []
    for row, err in zip(matrix, error):
        value = sum((a * s) for a, s in zip(row, secret)) + err
        out.append(value % q)
    return out
