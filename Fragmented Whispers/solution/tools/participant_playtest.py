"""Isolated participant-perspective playtest for Fragmented Whispers."""

from __future__ import annotations

import argparse
import io
import re
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path

from scapy.all import IP, rdpcap  # type: ignore[import-untyped]

DEFAULT_PCAP_NAME = "fragmented_whispers.pcap"
SIGNAL_SOURCE_IP = "10.77.5.23"
SIGNAL_DEST_IP = "10.77.5.1"
SIGNAL_IP_ID = 0x7331
SIGNAL_PROTO = 17
SIGNAL_SRC_PORT = 45123
SIGNAL_DST_PORT = 31337
FLAG_RE = re.compile(r"ZeroSecure_CTF\{[^}]+\}")


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def _ip_header_checksum_valid(ip_packet: IP) -> bool:
    ihl = int(ip_packet.ihl) if ip_packet.ihl is not None else 5
    header = bytes(ip_packet)[: ihl * 4]
    return _internet_checksum(header) == 0


def _extract_zip_bytes(pcap_path: Path) -> tuple[bytes, int, int]:
    packets = rdpcap(str(pcap_path))

    rows: dict[int, tuple[bool, bytes]] = {}
    total_fragments_seen = 0

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        ip_packet = packet[IP]
        if int(ip_packet.proto) != SIGNAL_PROTO:
            continue
        if str(ip_packet.src) != SIGNAL_SOURCE_IP or str(ip_packet.dst) != SIGNAL_DEST_IP:
            continue
        if int(ip_packet.id) != SIGNAL_IP_ID:
            continue

        is_fragment = int(ip_packet.frag) > 0 or (int(ip_packet.flags) & 0x1) == 1
        if not is_fragment:
            continue

        total_fragments_seen += 1

        if not _ip_header_checksum_valid(ip_packet):
            continue

        offset = int(ip_packet.frag) * 8
        payload = bytes(ip_packet.payload)
        if not payload:
            continue

        if offset in rows:
            raise ValueError(f"Duplicate checksum-valid fragment offset found: {offset}")

        rows[offset] = ((int(ip_packet.flags) & 0x1) == 1, payload)

    if not rows:
        raise ValueError("No checksum-valid signal fragments recovered")

    ordered = sorted(rows.items(), key=lambda item: item[0])
    if ordered[0][0] != 0:
        raise ValueError("Missing fragment offset 0 in checksum-valid stream")

    end_candidates = [offset + len(payload) for offset, (more_fragments, payload) in ordered if not more_fragments]
    if not end_candidates:
        raise ValueError("No terminating fragment (MF=0) found")

    datagram_end = max(end_candidates)
    datagram = bytearray(datagram_end)
    filled = bytearray(datagram_end)

    for offset, (_, payload) in ordered:
        stop = offset + len(payload)
        if stop > datagram_end:
            raise ValueError("Fragment extends beyond reconstructed datagram")
        if any(filled[offset:stop]):
            raise ValueError("Overlap remained among checksum-valid fragments")
        datagram[offset:stop] = payload
        filled[offset:stop] = b"\x01" * len(payload)

    if any(value == 0 for value in filled):
        raise ValueError("Gap detected in checksum-valid fragment stream")

    datagram_bytes = bytes(datagram)
    src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", datagram_bytes[:8])
    if src_port != SIGNAL_SRC_PORT or dst_port != SIGNAL_DST_PORT:
        raise ValueError("Unexpected UDP ports in reconstructed datagram")

    return datagram_bytes[8:udp_len], total_fragments_seen, len(ordered)


def _extract_flag(zip_bytes: bytes) -> str:
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
        temp_root = Path(tempfile.mkdtemp(prefix="fragmented_whispers_playtest_"))
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

    zip_bytes, total_fragments_seen, validated_fragments = _extract_zip_bytes(pcap_path)

    recovered_zip = isolated_dir / "recovered_payload.zip"
    recovered_zip.write_bytes(zip_bytes)

    flag = _extract_flag(zip_bytes)

    print(f"[playtest] total_candidate_fragments={total_fragments_seen}")
    print(f"[playtest] validated_signal_fragments={validated_fragments}")
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
