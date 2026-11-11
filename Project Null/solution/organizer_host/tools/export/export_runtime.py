from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HOST_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = HOST_ROOT.parent
MASTER = HOST_ROOT / "challenges" / "layers.master.json"
FINAL_ASSEMBLY = HOST_ROOT / "fragments" / "final-assembly.json"

PARTICIPANT_BACKEND_DATA = REPO_ROOT / "participant" / "backend" / "app" / "challenge_data"
PARTICIPANT_PUBLIC_LAYERS = REPO_ROOT / "participant" / "frontend" / "public" / "layers"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _run_lint() -> None:
    lint_script = HOST_ROOT / "tools" / "lint" / "layer_lint.py"
    proc = subprocess.run([sys.executable, str(lint_script)], capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit("export blocked by lint errors")


def _materialize_private_layers(layers: list[dict]) -> None:
    challenges_root = HOST_ROOT / "challenges"
    for layer in layers:
        layer_dir = challenges_root / layer["id"]
        layer_dir.mkdir(parents=True, exist_ok=True)
        _write_json(layer_dir / "layer.json", layer)


def _materialize_public_assets(layers: list[dict]) -> None:
    for layer in layers:
        layer_dir = PARTICIPANT_PUBLIC_LAYERS / layer["id"]
        layer_dir.mkdir(parents=True, exist_ok=True)
        asset_file = layer_dir / layer["public_asset"]
        if not asset_file.exists():
            asset_file.write_text(
                (
                    f"PROJECT: NULL placeholder asset for {layer['id']} ({layer['title']}).\n"
                    "Replace this file with authored public evidence before release.\n"
                ),
                encoding="utf-8",
            )


def export() -> None:
    _run_lint()

    master_data = json.loads(MASTER.read_text(encoding="utf-8"))
    final_data = json.loads(FINAL_ASSEMBLY.read_text(encoding="utf-8"))
    layers = master_data["layers"]

    _materialize_private_layers(layers)
    _materialize_public_assets(layers)

    layers_compiled = {
        "challenge": master_data["challenge"],
        "generated_at": datetime.now(UTC).isoformat(),
        "layers": [
            {
                "layer": layer["layer"],
                "id": layer["id"],
                "title": layer["title"],
                "act": layer["act"],
                "timer_seconds": layer["timer_seconds"],
                "public_asset": f"/layers/{layer['id']}/{layer['public_asset']}",
                "canonical_aliases": layer["canonical_aliases"],
                "false_positive_aliases": layer["false_positive_aliases"],
            }
            for layer in layers
        ],
    }

    fragments_compiled = {
        "generated_at": datetime.now(UTC).isoformat(),
        "layers": [
            {
                "layer": layer["layer"],
                "verified_fragment": layer["verified_fragment"],
                "poison_fragment": layer["poison_fragment"],
            }
            for layer in layers
        ],
    }

    final_compiled = {
        "generated_at": datetime.now(UTC).isoformat(),
        "requires_all_verified_layers": final_data["requires_all_verified_layers"],
        "reject_if_any_poison_fragment": final_data["reject_if_any_poison_fragment"],
        "final_flag": final_data["final_flag"],
    }

    _write_json(PARTICIPANT_BACKEND_DATA / "layers_compiled.json", layers_compiled)
    _write_json(PARTICIPANT_BACKEND_DATA / "fragments_compiled.json", fragments_compiled)
    _write_json(PARTICIPANT_BACKEND_DATA / "final_compiled.json", final_compiled)

    manifest = {
        "build_id": datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {
            "layers_master": str(MASTER.relative_to(REPO_ROOT)).replace("\\", "/"),
            "final_assembly": str(FINAL_ASSEMBLY.relative_to(REPO_ROOT)).replace("\\", "/"),
        },
        "artifacts": {
            "layers_compiled": {
                "path": "participant/backend/app/challenge_data/layers_compiled.json",
                "sha256": _sha256(PARTICIPANT_BACKEND_DATA / "layers_compiled.json"),
            },
            "fragments_compiled": {
                "path": "participant/backend/app/challenge_data/fragments_compiled.json",
                "sha256": _sha256(PARTICIPANT_BACKEND_DATA / "fragments_compiled.json"),
            },
            "final_compiled": {
                "path": "participant/backend/app/challenge_data/final_compiled.json",
                "sha256": _sha256(PARTICIPANT_BACKEND_DATA / "final_compiled.json"),
            },
        },
    }
    _write_json(PARTICIPANT_BACKEND_DATA / "export_manifest.json", manifest)

    print("Export complete")


if __name__ == "__main__":
    export()
