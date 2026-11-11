"""Obfuscation helpers used to derive deterministic seeds at runtime."""

from __future__ import annotations

from .params import CORPUS_TEXT


def _mix64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 31
    return value


def derive_base_seed(text: str = CORPUS_TEXT) -> int:
    vowels = sum(1 for ch in text.lower() if ch in "aeiou")
    weighted = sum((idx + 1) * ord(ch) for idx, ch in enumerate(text))
    raw = vowels * len(text) + weighted
    return _mix64(raw)


def derive_matrix_seed(counter: int = 0) -> int:
    base = derive_base_seed()
    salt = 0x9E3779B97F4A7C15 * (counter + 1)
    return _mix64(base ^ salt ^ (len(CORPUS_TEXT) << 17))
