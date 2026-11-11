from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import random
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import AES

from src.challenge_config import ChallengeConfig, TRUE_FLAG
from src.covert_flow import build_covert_pcap, key_to_bits
from src.flag_policy import DECOY_STRINGS
from src.pvd_stego import bytes_to_bits, embed_payload_pvd
from src.terminal_style import TerminalStyle


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def random_bytes(length: int, rng: random.Random | None) -> bytes:
    if rng is None:
        return os.urandom(length)
    return bytes(rng.randrange(0, 256) for _ in range(length))


def encrypt_flag(flag: str, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pkcs7_pad(flag.encode("utf-8")))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_artifacts(output_dir: Path, seed: int | None, force_color: bool) -> Tuple[Path, Path]:
    style = TerminalStyle(force_color=force_color)
    config = ChallengeConfig()

    participant_dir = output_dir / "participant"
    organizer_dir = output_dir / "organizer"
    participant_dir.mkdir(parents=True, exist_ok=True)
    organizer_dir.mkdir(parents=True, exist_ok=True)

    print(style.banner("Whispers in the Void - Builder"))
    print(style.info("Generating challenge artifacts"))

    rng = random.Random(seed) if seed is not None else None
    if seed is not None:
        print(style.warn(f"Deterministic seed mode enabled: {seed}"))

    key = random_bytes(32, rng)
    iv = random_bytes(16, rng)
    ciphertext = encrypt_flag(TRUE_FLAG, key, iv)
    payload = iv + ciphertext
    print(style.step(f"AES payload prepared: {len(payload)} bytes"))

    image = embed_payload_pvd(payload, width=config.width, height=config.height, seed=config.seed_default)

    png_in_memory = io.BytesIO()
    image.save(png_in_memory, format="PNG", optimize=True, compress_level=9)
    png_bytes = png_in_memory.getvalue()
    png_bits = bytes_to_bits(png_bytes)
    print(style.step(f"Cover PNG generated: {len(png_bytes)} bytes ({len(png_bits)} bits)"))

    pcap_path = participant_dir / "whispers_in_the_void.pcap"
    schedule = build_covert_pcap(
        png_bits=png_bits,
        key_bits=key_to_bits(key),
        config=config,
        seed=seed if seed is not None else config.seed_default,
        output_pcap_path=str(pcap_path),
    )
    print(style.step(f"PCAP written with {len(png_bits)} covert packets"))

    brief_path = participant_dir / "challenge.txt"
    brief_path.write_text(
        "Whispers in the Void\n"
        "--------------------\n"
        "A silent stream carries one truth and many dead ends.\n"
        "Recover the real flag.\n"
        "\n"
        "Format: zerosecurectf{...}\n",
        encoding="utf-8",
    )

    hints_path = participant_dir / "hints_schedule.txt"
    hints_path.write_text(
        "Hint schedule\n"
        "-------------\n"
        "T+2h: Not every stream that looks structured carries truth.\n"
        "T+4h: The key signal repeats. Group by index classes.\n"
        "T+6h: Average timing by modulo position; noise is deliberate.\n",
        encoding="utf-8",
    )

    deadends_path = participant_dir / "deadends.txt"
    deadends_path.write_text("\n".join(DECOY_STRINGS) + "\n", encoding="utf-8")

    sha_file = participant_dir / "SHA256SUMS.txt"
    sha_file.write_text(
        f"{sha256_file(pcap_path)}  {pcap_path.name}\n"
        f"{sha256_file(brief_path)}  {brief_path.name}\n",
        encoding="utf-8",
    )
    with sha_file.open("a", encoding="utf-8") as handle:
        handle.write(f"{sha256_file(deadends_path)}  {deadends_path.name}\n")
        handle.write(f"{sha256_file(hints_path)}  {hints_path.name}\n")

    answer_path = organizer_dir / "answer_key.json"
    answer_path.write_text(
        json.dumps(
            {
                "true_flag": TRUE_FLAG,
                "key_hex": key.hex(),
                "iv_hex": iv.hex(),
                "payload_size": len(payload),
                "png_bytes": len(png_bytes),
                "covert_packets": len(png_bits),
                "timing_base_us": config.base_delay_us,
                "timing_quantum_us": config.quantum_delay_us,
                "timing_jitter_us": config.jitter_us,
                "total_packets_target": config.total_packets_target,
                "covert_packets_target": config.pcap_total_bits_target,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    timing_path = organizer_dir / "timing_ground_truth.json"
    timing_path.write_text(
        json.dumps(
            {
                "deltas_us": schedule.deltas_us,
                "absolute_us": schedule.absolute_us,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    manifest_path = organizer_dir / "generation_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "seed": seed,
                "output_dir": str(output_dir),
                "participant_files": [
                    pcap_path.name,
                    brief_path.name,
                    deadends_path.name,
                    hints_path.name,
                    sha_file.name,
                ],
                "organizer_files": [
                    answer_path.name,
                    timing_path.name,
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(style.step("Participant and organizer bundles generated"))
    print(style.info(f"Participant folder: {participant_dir}"))
    print(style.info(f"Organizer folder: {organizer_dir}"))

    return pcap_path, answer_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Whispers in the Void challenge artifacts")
    parser.add_argument("--output", default="dist", help="Output directory for artifacts")
    parser.add_argument("--seed", type=int, default=None, help="Optional deterministic seed")
    parser.add_argument("--force-color", action="store_true", help="Force ANSI color output")
    args = parser.parse_args()

    output_dir = Path(args.output)
    generate_artifacts(output_dir=output_dir, seed=args.seed, force_color=args.force_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
