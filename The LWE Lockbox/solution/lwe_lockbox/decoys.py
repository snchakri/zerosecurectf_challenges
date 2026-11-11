"""Decoy output generation and attempt evaluation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List

from .noise_engine import hamming_distance
from .params import BOT_HINT_KEYWORDS, DECOY_FLAGS, TRUE_FLAG


@dataclass(frozen=True)
class AttemptResult:
    success: bool
    flag: str
    message: str
    hint_code: str
    decoy_vector: List[int] | None


def _contains_bot_markers(raw_fragments: Iterable[str]) -> bool:
    blob = " ".join(raw_fragments).lower()
    return any(token in blob for token in BOT_HINT_KEYWORDS)


def _pick_decoy_flag(fragment_digest: str) -> str:
    idx = int(fragment_digest[:8], 16) % len(DECOY_FLAGS)
    return DECOY_FLAGS[idx]


def _build_decoy_vector(e_hat: List[int], fragment_digest: str) -> List[int]:
    # False vector intentionally derived from the wrong digest path.
    salt = int(hashlib.sha256(("decoy:" + fragment_digest).encode("ascii")).hexdigest()[:6], 16)
    offset = (salt % 7) + 1
    return [x + offset if (i % 3 == 0) else x - offset for i, x in enumerate(e_hat)]


def evaluate_attempt(
    raw_fragments: Iterable[str],
    fragment_digest: str,
    e_hat: List[int],
    true_e: List[int],
) -> AttemptResult:
    if e_hat == true_e:
        return AttemptResult(
            success=True,
            flag=TRUE_FLAG,
            message="Vector match confirmed. True flag is obtainable only with the true vector.",
            hint_code="AUTH_TRUE_VECTOR",
            decoy_vector=None,
        )

    distance = hamming_distance(e_hat, true_e)
    bot_marked = _contains_bot_markers(raw_fragments)
    decoy_flag = _pick_decoy_flag(fragment_digest)
    decoy_vector = _build_decoy_vector(e_hat, fragment_digest)

    if bot_marked:
        msg = (
            "Automated solving signature detected. Enter the human path: verify shard integrity, "
            "reconstruct canonical order, and solve only from A, b, e_hat."
        )
        hint = "BAIT_AUTOMATION_PATH"
    elif distance < len(true_e) // 3:
        msg = (
            "Near alignment in noisy lattice coordinates, but canonical vector check failed. "
            "Do not trust heuristic shortcuts."
        )
        hint = "BAIT_NEAR_MATCH"
    else:
        msg = (
            "Noise mismatch: derived vector is non-canonical. Re-check all six fragments and retry."
        )
        hint = "BAIT_VECTOR_MISMATCH"

    return AttemptResult(
        success=False,
        flag=decoy_flag,
        message=msg,
        hint_code=hint,
        decoy_vector=decoy_vector,
    )
