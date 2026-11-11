"""Isolated participant-perspective playtest for Ping Pong Exfiltration."""

from __future__ import annotations

import argparse
import io
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from scapy.all import ICMP, Raw, rdpcap  # type: ignore[import-untyped]

DEFAULT_PCAP_NAME = "ping_pong_exfiltration.pcap"
SIGNAL_IDENTIFIER = 0x1337
WINDOWS_PING_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"
PAYLOAD_SIZE_BYTES = len(WINDOWS_PING_PAYLOAD)
FLAG_RE = re.compile(r"ZeroSecure_CTF\{[^}]+\}")


def _recover_signal_zip_bytes(pcap_path: Path) -> tuple[bytes, int, int]:
    packets = rdpcap(str(pcap_path))

    signal_rows: list[tuple[int, int]] = []
    request_total = 0

    for packet in packets:
        if not packet.haslayer(ICMP):
            continue

        icmp = packet[ICMP]
        if int(icmp.type) != 8:
            continue

        request_total += 1

        if int(icmp.id) != SIGNAL_IDENTIFIER:
            continue
        if not packet.haslayer(Raw):
            continue

        payload = bytes(packet[Raw].load)
        if len(payload) != PAYLOAD_SIZE_BYTES:
            continue
        if payload[1:] != WINDOWS_PING_PAYLOAD[1:]:
            continue

        signal_rows.append((int(icmp.seq), payload[0]))

    signal_rows.sort(key=lambda row: row[0])
    sequences = [row[0] for row in signal_rows]
    if sequences != list(range(len(signal_rows))):
        raise ValueError("Signal sequence is not contiguous; extracted stream is unsafe")

    return bytes(row[1] for row in signal_rows), request_total, len(signal_rows)


def _recover_flag_from_zip_bytes(zip_bytes: bytes) -> str:
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    if "flag.txt" not in archive.namelist():
        raise ValueError("Recovered zip did not include flag.txt")

    text = archive.read("flag.txt").decode("utf-8").strip()
    match = FLAG_RE.search(text)
    if not match:
        raise ValueError("Flag pattern not found in recovered zip")
    return match.group(0)


def run_playtest(source_dir: Path, work_dir: Path | None = None) -> tuple[str, Path]:
    if work_dir is None:
        temp_root = Path(tempfile.mkdtemp(prefix="ping_pong_exfiltration_playtest_"))
    else:
        temp_root = work_dir
        if temp_root.exists():
            shutil.rmtree(temp_root)
        temp_root.mkdir(parents=True, exist_ok=True)

    isolated_dir = temp_root / "participant-deliverables"
    shutil.copytree(source_dir, isolated_dir)

    pcap_path = isolated_dir / DEFAULT_PCAP_NAME
    if not pcap_path.exists():
        raise FileNotFoundError(f"Missing pcap in isolated view: {pcap_path}")

    zip_bytes, request_total, signal_count = _recover_signal_zip_bytes(pcap_path)
    recovered_zip = isolated_dir / "recovered_payload.zip"
    recovered_zip.write_bytes(zip_bytes)

    flag = _recover_flag_from_zip_bytes(zip_bytes)

    print(f"[playtest] total_echo_requests={request_total}")
    print(f"[playtest] signal_echo_requests={signal_count}")
    print(f"[playtest] reconstructed_zip_bytes={len(zip_bytes)}")
    print(f"[playtest] solved_flag={flag}")
    print(f"[playtest] isolated_dir={isolated_dir}")

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
