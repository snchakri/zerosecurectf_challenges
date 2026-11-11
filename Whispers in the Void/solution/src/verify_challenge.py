from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import List

from Crypto.Cipher import AES
from PIL import Image
from scapy.all import rdpcap

from src.challenge_config import ChallengeConfig, TRUE_FLAG
from src.covert_flow import recover_payload_bits_from_packets
from src.flag_policy import is_accepted_submission, is_flag_format, is_true_flag
from src.pvd_stego import bits_to_bytes, extract_payload_pvd
from src.terminal_style import TerminalStyle


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding bytes")
    return data[:-pad]


def recover_key_bits_from_timing(times_us: List[int], config: ChallengeConfig) -> List[int]:
    if len(times_us) < 256:
        raise ValueError("not enough packets to recover timing key")

    # First covert packet timestamp is measured from t=0 in the generator.
    deltas = [times_us[0]] + [times_us[i] - times_us[i - 1] for i in range(1, len(times_us))]
    buckets = [[] for _ in range(256)]

    for i, delta in enumerate(deltas):
        buckets[i % 256].append(delta)

    threshold = config.base_delay_us + (config.quantum_delay_us // 2)
    bits: List[int] = []
    for group in buckets:
        if not group:
            bits.append(0)
            continue
        avg = sum(group) / len(group)
        bits.append(1 if avg > threshold else 0)
    return bits


def bits_to_key(bits: List[int]) -> bytes:
    if len(bits) != 256:
        raise ValueError("expected 256 bits")
    out = bytearray()
    for i in range(0, 256, 8):
        value = 0
        for b in bits[i : i + 8]:
            value = (value << 1) | (b & 1)
        out.append(value)
    return bytes(out)


def verify(bundle_root: Path, force_color: bool) -> int:
    style = TerminalStyle(force_color=force_color)
    config = ChallengeConfig()

    participant = bundle_root / "participant"
    organizer = bundle_root / "organizer"

    pcap_path = participant / "whispers_in_the_void.pcap"
    truth_path = organizer / "timing_ground_truth.json"
    deadends_path = participant / "deadends.txt"

    if not pcap_path.exists():
        print(style.fail(f"Missing PCAP: {pcap_path}"))
        return 2
    if not truth_path.exists():
        print(style.fail(f"Missing timing truth: {truth_path}"))
        return 2
    if not deadends_path.exists():
        print(style.fail(f"Missing decoy list: {deadends_path}"))
        return 2

    print(style.banner("Whispers in the Void - Verifier"))
    packets = rdpcap(str(pcap_path))
    payload_bits, times_us = recover_payload_bits_from_packets(packets, config)

    if not payload_bits:
        print(style.fail("No covert payload bits recovered"))
        return 3
    print(style.step(f"Recovered payload bits: {len(payload_bits)}"))

    png_bytes = bits_to_bytes(payload_bits)
    if png_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        print(style.fail("Recovered bytes do not start with a PNG signature"))
        return 3

    image = Image.open(io.BytesIO(png_bytes))
    payload = extract_payload_pvd(image)
    if len(payload) < 17:
        print(style.fail("Recovered payload from PVD is too short"))
        return 3

    iv = payload[:16]
    ciphertext = payload[16:]

    key_bits = recover_key_bits_from_timing(times_us, config)
    key = bits_to_key(key_bits)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    try:
        plaintext = pkcs7_unpad(cipher.decrypt(ciphertext)).decode("utf-8")
    except Exception as exc:  # pylint: disable=broad-except
        print(style.fail(f"Decryption failed: {exc}"))
        return 4

    if not is_accepted_submission(plaintext):
        print(style.fail("Recovered plaintext is not the canonical true flag"))
        return 4

    with truth_path.open("r", encoding="utf-8") as handle:
        truth = json.load(handle)
    expected = truth.get("deltas_us", [])

    observed = [times_us[0]] + [times_us[i] - times_us[i - 1] for i in range(1, len(times_us))]
    compare_len = min(len(expected), len(observed))
    if compare_len == 0:
        print(style.fail("No timing deltas available for drift verification"))
        return 5

    drift = [abs(int(expected[i]) - int(observed[i])) for i in range(compare_len)]
    max_drift = max(drift)
    if max_drift > 2:
        print(style.fail(f"Timing drift too high after serialization: max {max_drift} us"))
        return 5

    for line in deadends_path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value:
            continue
        if is_flag_format(value) and is_true_flag(value):
            print(style.fail("Dead-end artifact leaked the true flag"))
            return 6
        if is_accepted_submission(value):
            print(style.fail("Dead-end artifact contains an accepted submission"))
            return 6

    print(style.step("True flag recovered successfully"))
    print(style.info(f"Flag: {plaintext}"))
    print(style.step(f"Timing drift check passed (max {max_drift} us)"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify generated challenge artifacts")
    parser.add_argument("--bundle", default="dist", help="Bundle root containing participant/organizer")
    parser.add_argument("--force-color", action="store_true", help="Force ANSI color output")
    args = parser.parse_args()
    return verify(bundle_root=Path(args.bundle), force_color=args.force_color)


if __name__ == "__main__":
    raise SystemExit(main())
