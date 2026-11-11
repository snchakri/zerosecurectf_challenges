"""Reference solver for Rogue Edge Sensor MQTT telemetry steganography."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from challenge_config import DEFAULT_PCAP_NAME, FLAG_PREFIX, TOPIC_SIGNAL

FLAG_RE = re.compile(r"ZeroSecure_CTF\{[^}]+\}")


def _find_tshark(tshark_bin: str) -> str:
    resolved = shutil.which(tshark_bin)
    if not resolved:
        raise FileNotFoundError(f"tshark not found in PATH: {tshark_bin}")
    return resolved


def extract_signal_payload_strings(pcap_path: Path, tshark_bin: str = "tshark") -> list[str]:
    tshark = _find_tshark(tshark_bin)
    query = f'mqtt && mqtt.topic == "{TOPIC_SIGNAL}"'
    cmd = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        query,
        "-T",
        "fields",
        "-e",
        "mqtt.msg",
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _json_from_tshark_field(raw: str) -> dict:
    raw_stripped = raw.strip()

    # Some tshark builds emit mqtt.msg as hexadecimal bytes instead of literal JSON.
    if raw_stripped and len(raw_stripped) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in raw_stripped):
        try:
            decoded = bytes.fromhex(raw_stripped).decode("utf-8")
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, json.JSONDecodeError):
            pass

    # tshark may return plain JSON text or a quoted/escaped JSON string.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            return json.loads(parsed)
    except json.JSONDecodeError:
        pass

    # Last resort: unescape common tshark quoting wrappers.
    cleaned = raw.strip().strip('"')
    cleaned = cleaned.replace('\\"', '"')
    return json.loads(cleaned)


def _sensor_raw_to_ascii(sensor_raw: str) -> int:
    fraction = sensor_raw.split(".", 1)[1] if "." in sensor_raw else sensor_raw
    digits = "".join(ch for ch in fraction if ch.isdigit())[:3]
    if len(digits) != 3:
        raise ValueError(f"Invalid sensor_raw format: {sensor_raw}")
    return int(digits)


def decode_from_payload_objects(payload_objects: list[dict]) -> tuple[str, str]:
    decoded_chars: list[str] = []
    for obj in payload_objects:
        sensor_raw = str(obj.get("sensor_raw", ""))
        try:
            value = _sensor_raw_to_ascii(sensor_raw)
        except ValueError:
            continue

        if 32 <= value <= 126:
            decoded_chars.append(chr(value))

    decoded_stream = "".join(decoded_chars)
    match = FLAG_RE.search(decoded_stream)
    if not match:
        raise ValueError("Flag pattern not found in decoded stream")
    return match.group(0), decoded_stream


def solve_pcap(pcap_path: Path, tshark_bin: str = "tshark") -> tuple[str, str]:
    payload_lines = extract_signal_payload_strings(pcap_path=pcap_path, tshark_bin=tshark_bin)
    payload_objects = [_json_from_tshark_field(line) for line in payload_lines]
    return decode_from_payload_objects(payload_objects)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solve Rogue Edge Sensor PCAP")
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / DEFAULT_PCAP_NAME,
        help="Path to challenge PCAP",
    )
    parser.add_argument("--tshark-bin", default="tshark", help="tshark binary path")
    parser.add_argument(
        "--print-stream",
        action="store_true",
        help="Print full decoded printable stream in addition to flag",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    flag, stream = solve_pcap(pcap_path=args.pcap.resolve(), tshark_bin=args.tshark_bin)
    if not flag.startswith(FLAG_PREFIX):
        raise ValueError("Decoded flag does not match expected prefix")

    print(flag)
    if args.print_stream:
        print("--- decoded stream ---")
        print(stream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
