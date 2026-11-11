"""Noise vector generation from deterministic digest-derived seeds."""

from __future__ import annotations

import hashlib
import random
from typing import Iterable, List

from .params import M, NOISE_MAX, NOISE_MIN


def seed_from_digest(digest_hex: str, label: str = "LWE_NOISE_V1") -> int:
    payload = f"{label}:{digest_hex}".encode("ascii")
    seed_hex = hashlib.sha256(payload).hexdigest()[:16]
    return int(seed_hex, 16)


def generate_error_vector(
    digest_hex: str,
    m: int = M,
    low: int = NOISE_MIN,
    high: int = NOISE_MAX,
    label: str = "LWE_NOISE_V1",
) -> List[int]:
    rng = random.Random(seed_from_digest(digest_hex, label=label))
    return [rng.randint(low, high) for _ in range(m)]


def hamming_distance(a: Iterable[int], b: Iterable[int]) -> int:
    list_a = list(a)
    list_b = list(b)
    if len(list_a) != len(list_b):
        raise ValueError("vectors must have the same length")
    return sum(1 for x, y in zip(list_a, list_b) if x != y)
