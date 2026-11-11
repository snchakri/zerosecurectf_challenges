"""Isolated participant-perspective playtest runner.

This script copies only participant-deliverables into a temporary directory,
then solves the challenge from that isolated copy using tshark and stdlib JSON.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

TOPIC_SIGNAL = "samavarthan/halls/main/sensor1"
TOPIC_DECOY_A = "samavarthan/halls/main/sensor2"
TOPIC_DECOY_B = "samavarthan/halls/annex/sensor12"

FLAG_RE = re.compile(r"ZeroSecure_CTF\{[^}]+\}")


def _run_tshark_rows(pcap_path: Path) -> list[str]:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        "mqtt.msg",
        "-T",
        "fields",
        "-e",
        "mqtt.topic",
        "-e",
        "mqtt.msg",
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def _parse_payload(raw: str) -> dict:
    raw_stripped = raw.strip()

    # tshark may emit mqtt.msg as hexadecimal bytes.
    if raw_stripped and len(raw_stripped) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in raw_stripped):
        try:
            return json.loads(bytes.fromhex(raw_stripped).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            pass

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            return json.loads(parsed)
    except json.JSONDecodeError:
        pass

    cleaned = raw.strip().strip('"').replace('\\"', '"')
    return json.loads(cleaned)


def _sensor_raw_to_ascii_value(sensor_raw: str) -> int | None:
    fraction = sensor_raw.split(".", 1)[1] if "." in sensor_raw else sensor_raw
    digits = "".join(ch for ch in fraction if ch.isdigit())[:3]
    if len(digits) != 3:
        return None
    return int(digits)


def run_playtest(source_dir: Path, work_dir: Path | None = None) -> tuple[str, Path]:
    if work_dir is None:
        temp_path = Path(tempfile.mkdtemp(prefix="rogue_edge_sensor_playtest_"))
    else:
        temp_path = work_dir
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True, exist_ok=True)

    isolated_dir = temp_path / "participant-deliverables"
    shutil.copytree(source_dir, isolated_dir)

    pcap_path = isolated_dir / "rogue_edge_sensor.pcap"
    if not pcap_path.exists():
        raise FileNotFoundError(f"Missing pcap in isolated view: {pcap_path}")

    rows = _run_tshark_rows(pcap_path)

    counts = {
        TOPIC_SIGNAL: 0,
        TOPIC_DECOY_A: 0,
        TOPIC_DECOY_B: 0,
    }

    signal_payloads: list[dict] = []
    for row in rows:
        parts = row.split("\t", 1)
        if len(parts) != 2:
            continue
        topic, raw_msg = parts
        if topic not in counts:
            continue

        counts[topic] += 1
        payload = _parse_payload(raw_msg)
        if topic == TOPIC_SIGNAL:
            signal_payloads.append(payload)

    total = sum(counts.values())
    print(f"[playtest] total_mqtt={total}")
    for topic, count in counts.items():
        share = (count / total) if total else 0.0
        print(f"[playtest] topic={topic} count={count} share={share:.4f}")

    decoded_chars: list[str] = []
    for payload in signal_payloads:
        value = _sensor_raw_to_ascii_value(str(payload.get("sensor_raw", "")))
        if value is None:
            continue
        if 32 <= value <= 126:
            decoded_chars.append(chr(value))

    stream = "".join(decoded_chars)
    match = FLAG_RE.search(stream)
    if not match:
        raise ValueError("Flag pattern not found in participant decoded stream")

    flag = match.group(0)
    print(f"[playtest] solved_flag={flag}")
    print(f"[playtest] isolated_dir={isolated_dir}")
    print("[playtest] files=" + ", ".join(sorted(p.name for p in isolated_dir.iterdir())))

    return flag, isolated_dir


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run isolated participant playtest")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables",
        help="Directory containing participant deliverables",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Optional deterministic temp directory path",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    run_playtest(source_dir=args.source_dir.resolve(), work_dir=args.work_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
