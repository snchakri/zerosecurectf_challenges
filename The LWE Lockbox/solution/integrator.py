from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List

from lwe_lockbox.decoys import AttemptResult, evaluate_attempt
from lwe_lockbox.flag_engine import compute_locked_vector, encode_flag_to_secret
from lwe_lockbox.fragments import build_slot_values, digest_from_fragments
from lwe_lockbox.matrix_engine import generate_full_rank_matrix, rank_mod_q
from lwe_lockbox.noise_engine import generate_error_vector
from lwe_lockbox.params import M, N, Q, TRUE_FRAGMENT_DIGEST


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_matrix(path: Path, matrix: List[List[int]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in matrix:
            f.write(" ".join(str(value) for value in row))
            f.write("\n")


def _write_vector(path: Path, vector: List[int]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for value in vector:
            f.write(f"{value}\n")


def _collect_fragments_interactive() -> List[str]:
    print("Input the 6 fragments (format: Sx=<value> or optional recovery R:Sx=<value>):")
    fragments: List[str] = []
    for idx in range(1, 7):
        fragments.append(input(f"Fragment {idx}: ").strip())
    return fragments


def _render_banner() -> str:
    return (
        "\n=== ZeroSecure LWE Lockbox ===\n"
        "Artifacts generated: A_matrix.txt, b_vector.txt, e_hat_vector.txt.\n"
        "Solve: (b - e_hat) = A*s (mod 10007), then decode s as ASCII with deterministic padding removal.\n"
        "Only the true vector path can unlock the true flag.\n"
    )


def run_challenge(raw_fragments: Iterable[str], out_dir: Path) -> Dict[str, object]:
    fragments = list(raw_fragments)
    slot_values = build_slot_values(fragments)
    participant_digest = digest_from_fragments(fragments)

    matrix_a, matrix_seed, reseed_counter = generate_full_rank_matrix(m=M, n=N, q=Q)
    matrix_rank = rank_mod_q(matrix_a, q=Q)

    secret_s = encode_flag_to_secret()
    true_e = generate_error_vector(TRUE_FRAGMENT_DIGEST, m=M)
    e_hat = generate_error_vector(participant_digest, m=M)
    vector_b = compute_locked_vector(matrix=matrix_a, secret=secret_s, error=true_e, q=Q)

    out_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = out_dir / "A_matrix.txt"
    b_path = out_dir / "b_vector.txt"
    e_hat_path = out_dir / "e_hat_vector.txt"

    _write_matrix(matrix_path, matrix_a)
    _write_vector(b_path, vector_b)
    _write_vector(e_hat_path, e_hat)

    result: AttemptResult = evaluate_attempt(
        raw_fragments=fragments,
        fragment_digest=participant_digest,
        e_hat=e_hat,
        true_e=true_e,
    )

    if result.decoy_vector is not None:
        _write_vector(out_dir / "false_vector_bait.txt", result.decoy_vector)

    metadata = {
        "n": N,
        "m": M,
        "q": Q,
        "matrix_seed": matrix_seed,
        "matrix_reseed_counter": reseed_counter,
        "matrix_rank_mod_q": matrix_rank,
        "participant_digest": participant_digest,
        "hint_code": result.hint_code,
        "checksums": {
            "A_matrix.txt": _sha256_file(matrix_path),
            "b_vector.txt": _sha256_file(b_path),
            "e_hat_vector.txt": _sha256_file(e_hat_path),
        },
        "provided_slots": sorted(slot_values.keys()),
    }

    metadata_path = out_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return {
        "result": result,
        "metadata": metadata,
        "artifact_dir": str(out_dir),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ZeroSecure CTF final integrator")
    parser.add_argument("fragments", nargs="*", help="Exactly six fragments")
    parser.add_argument("--out-dir", default="outputs", help="Output directory for artifacts")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    raw_fragments = args.fragments if args.fragments else _collect_fragments_interactive()

    try:
        outcome = run_challenge(raw_fragments=raw_fragments, out_dir=Path(args.out_dir))
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1

    result: AttemptResult = outcome["result"]
    print(_render_banner())
    print(f"Artifact directory: {outcome['artifact_dir']}")
    print(f"Status message: {result.message}")

    if result.success:
        print("AUTHENTIC RESULT: true vector match confirmed.")
        print(f"TRUE FLAG: {result.flag}")
        return 0

    print("Result: canonical vector mismatch.")
    print(f"Decoy output (ignore for scoring): {result.flag}")
    print("If your fragments are correct, solve externally and retry with verified shard values.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
