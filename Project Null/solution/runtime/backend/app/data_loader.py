from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LayerDef:
    layer: int
    id: str
    title: str
    act: int
    timer_seconds: int
    public_asset: str
    canonical_aliases: tuple[str, ...]
    false_positive_aliases: tuple[str, ...]
    verified_fragment: str
    poison_fragment: str


@dataclass(frozen=True)
class CompiledData:
    layers: dict[int, LayerDef]
    final_flag: str
    requires_all_verified_layers: int
    reject_if_any_poison_fragment: bool


DATA_DIR = Path(__file__).resolve().parent / "challenge_data"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_compiled_manifest() -> None:
    manifest_path = DATA_DIR / "export_manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("missing export_manifest.json")

    manifest = _read_json(manifest_path)
    for key in ("layers_compiled", "fragments_compiled", "final_compiled"):
        artifact = manifest["artifacts"][key]
        artifact_path = DATA_DIR / Path(artifact["path"]).name
        actual = _sha256(artifact_path)
        expected = artifact["sha256"]
        if actual != expected:
            raise RuntimeError(f"integrity check failed for {key}: expected {expected}, got {actual}")


def load_compiled_data() -> CompiledData:
    verify_compiled_manifest()

    layers_doc = _read_json(DATA_DIR / "layers_compiled.json")
    frags_doc = _read_json(DATA_DIR / "fragments_compiled.json")
    final_doc = _read_json(DATA_DIR / "final_compiled.json")

    fragments_by_layer = {row["layer"]: row for row in frags_doc["layers"]}
    layers: dict[int, LayerDef] = {}

    for row in layers_doc["layers"]:
        layer_number = row["layer"]
        frag = fragments_by_layer[layer_number]
        layers[layer_number] = LayerDef(
            layer=layer_number,
            id=row["id"],
            title=row["title"],
            act=row["act"],
            timer_seconds=row["timer_seconds"],
            public_asset=row["public_asset"],
            canonical_aliases=tuple(alias.lower() for alias in row["canonical_aliases"]),
            false_positive_aliases=tuple(alias.lower() for alias in row["false_positive_aliases"]),
            verified_fragment=frag["verified_fragment"],
            poison_fragment=frag["poison_fragment"],
        )

    return CompiledData(
        layers=layers,
        final_flag=final_doc["final_flag"],
        requires_all_verified_layers=final_doc["requires_all_verified_layers"],
        reject_if_any_poison_fragment=bool(final_doc["reject_if_any_poison_fragment"]),
    )
