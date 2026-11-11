"""Isolated participant-perspective playtest for Knock-Knock Joke."""

from __future__ import annotations

import argparse
import re
import shutil
import tempfile
from pathlib import Path

from scapy.all import IP, TCP, rdpcap  # type: ignore[import-untyped]

DEFAULT_PCAP_NAME = "knock_knock_joke.pcap"
FLAG_PREFIX = "ZeroSecure_CTF{"
FLAG_RE = re.compile(r"^ZeroSecure_CTF\{[^}]+\}$")
PORT_OFFSET_BASE = 5000
SIGNAL_ATTACKER_IP = "10.44.9.77"
SIGNAL_SERVER_IP = "10.44.9.10"
EPHEMERAL_MIN = 49152
EPHEMERAL_MAX = 65535


def _flags(tcp_layer: TCP) -> str:
    return str(tcp_layer.flags)


def _payload_empty(packet) -> bool:
    return len(bytes(packet[TCP].payload)) == 0


def _recover_flag(pcap_path: Path) -> tuple[str, int]:
    packets = rdpcap(str(pcap_path))

    syn_rows: list[tuple[float, int, int, int]] = []
    rst_rows: list[tuple[float, int, int, int]] = []

    for packet in packets:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        if ip.src == SIGNAL_ATTACKER_IP and ip.dst == SIGNAL_SERVER_IP and _flags(tcp) == "S":
            if not _payload_empty(packet):
                continue
            if not (EPHEMERAL_MIN <= int(tcp.sport) <= EPHEMERAL_MAX):
                continue
            syn_rows.append((float(packet.time), int(tcp.sport), int(tcp.dport), int(tcp.seq)))
        elif ip.src == SIGNAL_SERVER_IP and ip.dst == SIGNAL_ATTACKER_IP and _flags(tcp) == "RA":
            if not _payload_empty(packet):
                continue
            rst_rows.append((float(packet.time), int(tcp.sport), int(tcp.dport), int(tcp.ack)))

    if not syn_rows:
        raise ValueError("No candidate signal SYN packets found")

    used = [False for _ in rst_rows]
    decoded_chars: list[str] = []

    for syn_time, syn_sport, syn_dport, syn_seq in syn_rows:
        paired = False
        for idx, (rst_time, rst_sport, rst_dport, rst_ack) in enumerate(rst_rows):
            if used[idx]:
                continue
            if rst_sport != syn_dport or rst_dport != syn_sport:
                continue
            if rst_ack != syn_seq + 1:
                continue
            if rst_time < syn_time or (rst_time - syn_time) > 0.080:
                continue
            used[idx] = True
            paired = True
            break

        if not paired:
            raise ValueError("Signal SYN stream failed RST pairing validation")

        ascii_code = syn_dport - PORT_OFFSET_BASE
        if ascii_code < 32 or ascii_code > 126:
            raise ValueError("Decoded non-printable ASCII from signal ports")
        decoded_chars.append(chr(ascii_code))

    flag = "".join(decoded_chars)
    if not flag.startswith(FLAG_PREFIX):
        raise ValueError("Recovered text does not start with expected flag prefix")
    if not FLAG_RE.match(flag):
        raise ValueError("Recovered text does not match strict flag format")

    return flag, len(syn_rows)


def run_playtest(source_dir: Path, work_dir: Path | None = None) -> tuple[str, Path]:
    if work_dir is None:
        temp_root = Path(tempfile.mkdtemp(prefix="knock_knock_joke_playtest_"))
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

    flag, signal_count = _recover_flag(pcap_path)

    print(f"[playtest] signal_syn_packets={signal_count}")
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
