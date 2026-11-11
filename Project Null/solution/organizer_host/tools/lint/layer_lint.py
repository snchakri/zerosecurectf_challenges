from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MASTER = ROOT / "challenges" / "layers.master.json"

FRAGMENT_RE = re.compile(r"^shard::[0-9]{2}::[a-z0-9-]+$")
ALLOWED_TIMERS = {180, 195, 210, 240}


def load_layers() -> list[dict]:
    data = json.loads(MASTER.read_text(encoding="utf-8"))
    return data["layers"]


def lint(layers: list[dict]) -> list[str]:
    errors: list[str] = []
    if len(layers) != 30:
        errors.append(f"expected 30 layers, found {len(layers)}")

    layer_numbers = set()
    ids = set()
    canonical_seen = set()
    false_seen = set()
    fragments_seen = set()

    for layer in layers:
        n = layer["layer"]
        lid = layer["id"]
        if n in layer_numbers:
            errors.append(f"duplicate layer number {n}")
        layer_numbers.add(n)

        if lid in ids:
            errors.append(f"duplicate layer id {lid}")
        ids.add(lid)

        if layer["timer_seconds"] not in ALLOWED_TIMERS:
            errors.append(f"layer {n} has invalid timer {layer['timer_seconds']}")

        for key in layer.get("canonical_aliases", []):
            norm = key.lower().strip()
            if norm in canonical_seen:
                errors.append(f"duplicate canonical alias '{key}'")
            canonical_seen.add(norm)

        for key in layer.get("false_positive_aliases", []):
            norm = key.lower().strip()
            if norm in false_seen:
                errors.append(f"duplicate false-positive alias '{key}'")
            false_seen.add(norm)

        overlap = canonical_seen.intersection(false_seen)
        if overlap:
            errors.append(f"canonical/false-positive overlap found: {sorted(overlap)}")

        for frag_name in ("verified_fragment", "poison_fragment"):
            frag = layer[frag_name]
            if not FRAGMENT_RE.match(frag):
                errors.append(f"layer {n} has invalid {frag_name}: {frag}")
            if frag in fragments_seen:
                errors.append(f"duplicate fragment id {frag}")
            fragments_seen.add(frag)

        if n != int(lid.split("-")[-1]):
            errors.append(f"layer {n} id mismatch: {lid}")

    expected = set(range(1, 31))
    missing = sorted(expected - layer_numbers)
    extra = sorted(layer_numbers - expected)
    if missing:
        errors.append(f"missing layers: {missing}")
    if extra:
        errors.append(f"unexpected layers: {extra}")

    return errors


def main() -> int:
    layers = load_layers()
    errors = lint(layers)
    if errors:
        print("LINT FAILED")
        for err in errors:
            print(f" - {err}")
        return 1

    print("LINT OK: all layer checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
