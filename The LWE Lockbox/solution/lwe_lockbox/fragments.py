"""Fragment parsing and canonical digest generation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .params import CORE_SLOTS, RECOVERY_SLOT

_CORE_RE = re.compile(r"^(S[1-6])=(.{1,128})$")
_RECOVERY_RE = re.compile(r"^R:(S[1-6])=(.{1,128})$")


@dataclass(frozen=True)
class ParsedFragment:
    kind: str
    slot: str
    value: str


def normalize_fragment(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("empty fragment provided")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("fragment contains non-printable characters")
    return value


def parse_fragment(raw: str) -> ParsedFragment:
    text = normalize_fragment(raw)
    m_core = _CORE_RE.match(text)
    if m_core:
        return ParsedFragment(kind="core", slot=m_core.group(1), value=m_core.group(2))

    m_recovery = _RECOVERY_RE.match(text)
    if m_recovery:
        return ParsedFragment(kind="recovery", slot=m_recovery.group(1), value=m_recovery.group(2))

    raise ValueError(
        "invalid fragment format. Expected Sx=<value> or R:Sx=<value> where x is 1..6"
    )


def build_slot_values(raw_fragments: Iterable[str]) -> Dict[str, str]:
    fragments = list(raw_fragments)
    if len(fragments) != 6:
        raise ValueError("exactly six fragments are required")

    parsed: List[ParsedFragment] = [parse_fragment(item) for item in fragments]
    core_values: Dict[str, str] = {}
    recovery_value: ParsedFragment | None = None

    for item in parsed:
        if item.kind == "core":
            if item.slot in core_values:
                raise ValueError(f"duplicate core slot provided: {item.slot}")
            core_values[item.slot] = item.value
            continue

        if recovery_value is not None:
            raise ValueError("only one recovery fragment is allowed")
        recovery_value = item

    missing = [slot for slot in CORE_SLOTS if slot not in core_values]

    if not missing:
        if recovery_value is not None:
            raise ValueError("recovery fragment cannot be used when all six core slots are present")
        return {slot: core_values[slot] for slot in CORE_SLOTS}

    if len(missing) != 1:
        raise ValueError("exactly one core slot may be missing when using recovery")

    if recovery_value is None:
        raise ValueError("a recovery fragment is required when one core slot is missing")

    if recovery_value.slot != missing[0]:
        raise ValueError(
            f"recovery slot mismatch. Missing {missing[0]} but recovery targets {recovery_value.slot}"
        )

    core_values[missing[0]] = recovery_value.value
    return {slot: core_values[slot] for slot in CORE_SLOTS}


def canonical_master_string(slot_values: Dict[str, str]) -> str:
    return "".join(slot_values[slot] for slot in CORE_SLOTS)


def digest_from_fragments(raw_fragments: Iterable[str]) -> str:
    slots = build_slot_values(raw_fragments)
    master = canonical_master_string(slots)
    return hashlib.sha256(master.encode("utf-8")).hexdigest()


def classify_inputs_for_bait(raw_fragments: Iterable[str]) -> str:
    lowered = " ".join(item.lower() for item in raw_fragments)
    if "ai" in lowered or "bot" in lowered or "crawler" in lowered:
        return "automation_suspected"
    if RECOVERY_SLOT.lower() in lowered:
        return "recovery_path"
    return "standard"
