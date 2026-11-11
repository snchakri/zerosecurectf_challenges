"""Reference solver for Ping Pong Exfiltration."""

from __future__ import annotations

import argparse
import io
import re
import zipfile
from pathlib import Path

from scapy.all import ICMP, Raw, rdpcap  # type: ignore[import-untyped]

from challenge_config import DEFAULT_PCAP_NAME, FLAG_PREFIX, PAYLOAD_SIZE_BYTES, SIGNAL_IDENTIFIER, WINDOWS_PING_PAYLOAD

FLAG_RE = re.compile(r"ZeroSecure_CTF\{[^}]+\}")


def extract_signal_zip_bytes(pcap_path: Path) -> bytes:
    packets = rdpcap(str(pcap_path))

    signal_rows: list[tuple[int, int]] = []
    for packet in packets:
        if not packet.haslayer(ICMP):
            continue

        icmp = packet[ICMP]
        if int(icmp.type) != 8:
            continue
        if int(icmp.id) != SIGNAL_IDENTIFIER:
            continue
        if not packet.haslayer(Raw):
            continue

        payload = bytes(packet[Raw].load)
        if len(payload) != PAYLOAD_SIZE_BYTES:
            raise ValueError(f"Unexpected payload length for signal packet: {len(payload)}")
        if payload[1:] != WINDOWS_PING_PAYLOAD[1:]:
            raise ValueError("Signal payload bytes 1..N do not match expected Windows ping padding")

        signal_rows.append((int(icmp.seq), payload[0]))

    if not signal_rows:
        raise ValueError("No signal packets found using discriminator icmp.id==0x1337")

    signal_rows.sort(key=lambda row: row[0])
    sequences = [row[0] for row in signal_rows]
    expected = list(range(len(signal_rows)))
    if sequences != expected:
        raise ValueError(
            "Signal packet sequence is not contiguous from 0..N-1; "
            "zip reconstruction would be unsafe"
        )

    return bytes(row[1] for row in signal_rows)


def extract_flag_from_zip_bytes(zip_bytes: bytes) -> str:
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = archive.namelist()

    if "flag.txt" not in names:
        raise ValueError("Expected flag.txt inside reconstructed zip")

    flag_text = archive.read("flag.txt").decode("utf-8").strip()
    if not flag_text.startswith(FLAG_PREFIX):
        raise ValueError("Recovered flag has unexpected prefix")

    match = FLAG_RE.search(flag_text)
    if not match:
        raise ValueError("Flag pattern not found in reconstructed zip")

    return match.group(0)


def solve_pcap(pcap_path: Path, output_zip: Path) -> tuple[str, int]:
    zip_bytes = extract_signal_zip_bytes(pcap_path=pcap_path)
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    output_zip.write_bytes(zip_bytes)

    flag = extract_flag_from_zip_bytes(zip_bytes)
    return flag, len(zip_bytes)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solve Ping Pong Exfiltration PCAP")
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / DEFAULT_PCAP_NAME,
        help="Path to challenge PCAP",
    )
    parser.add_argument(
        "--output-zip",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / "recovered_payload.zip",
        help="Where to write reconstructed ZIP bytes",
    )
    parser.add_argument("--print-stats", action="store_true", help="Print zip reconstruction size")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    pcap_path = args.pcap.resolve()
    output_zip = args.output_zip.resolve()

    flag, zip_size = solve_pcap(pcap_path=pcap_path, output_zip=output_zip)
    print(flag)
    if args.print_stats:
        print(f"[stats] reconstructed_zip_bytes={zip_size}")
        print(f"[stats] output_zip={output_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
