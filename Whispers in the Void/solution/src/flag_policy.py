from __future__ import annotations

import re
from typing import List

from src.challenge_config import TRUE_FLAG


FLAG_PATTERN = re.compile(r"^zerosecurectf\{[a-zA-Z0-9_\-]+\}$")


DECOY_STRINGS: List[str] = [
    "you_are_listening_to_the_wrong_silence",
    "DEAD END: timing without modulo averaging will lie to you",
    "WRONG PATH: this stream does not carry truth",
    "zerosecurectf{almost_but_not_the_void}",
    "zerosecurectf{too_fast_too_noisy}",
]


def is_flag_format(value: str) -> bool:
    return bool(FLAG_PATTERN.match(value.strip()))


def is_true_flag(value: str) -> bool:
    return value.strip() == TRUE_FLAG


def is_accepted_submission(value: str) -> bool:
    return is_flag_format(value) and is_true_flag(value)
