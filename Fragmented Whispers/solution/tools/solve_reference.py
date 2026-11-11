"""Reference solver for Fragmented Whispers."""

from __future__ import annotations

import argparse
import io
import re
import struct
import zipfile
from pathlib import Path

from scapy.all import IP, rdpcap  # type: ignore[import-untyped]

from challenge_config import (
    DEFAULT_PCAP_NAME,
    FLAG_PREFIX,
    SIGNAL_DEST_IP,
    SIGNAL_DST_PORT,
    SIGNAL_IP_ID,
    SIGNAL_PROTO,
    SIGNAL_SOURCE_IP,
    SIGNAL_SRC_PORT,
)

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


def _extract_fragment_rows(pcap_path: Path) -> list[tuple[int, bool, bytes]]:
    packets = rdpcap(str(pcap_path))

    rows: list[tuple[int, bool, bytes]] = []
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

        if not _ip_header_checksum_valid(ip_packet):
            continue

        payload = bytes(ip_packet.payload)
        if not payload:
            continue

        rows.append((int(ip_packet.frag) * 8, (int(ip_packet.flags) & 0x1) == 1, payload))

    return rows


def extract_signal_zip_bytes(pcap_path: Path) -> tuple[bytes, int]:
    rows = _extract_fragment_rows(pcap_path=pcap_path)
    if not rows:
        raise ValueError("No checksum-valid signal fragments found for configured tuple")

    fragment_map: dict[int, tuple[bool, bytes]] = {}
    for offset_bytes, more_fragments, payload in rows:
        if offset_bytes in fragment_map:
            raise ValueError(f"Duplicate checksum-valid fragment offset found: {offset_bytes}")
        fragment_map[offset_bytes] = (more_fragments, payload)

    ordered = sorted(fragment_map.items(), key=lambda item: item[0])
    if ordered[0][0] != 0:
        raise ValueError("Reassembly failed: first fragment (offset 0) is missing")

    end_candidates = [offset + len(payload) for offset, (more_fragments, payload) in ordered if not more_fragments]
    if not end_candidates:
        raise ValueError("Reassembly failed: no terminal fragment found (MF=0)")

    datagram_end = max(end_candidates)
    datagram = bytearray(datagram_end)
    filled = bytearray(datagram_end)

    for offset, (_, payload) in ordered:
        stop = offset + len(payload)
        if stop > datagram_end:
            raise ValueError("Reassembly failed: fragment extends beyond declared datagram end")
        if any(filled[offset:stop]):
            raise ValueError("Reassembly failed: overlap remained among checksum-valid fragments")

        datagram[offset:stop] = payload
        filled[offset:stop] = b"\x01" * len(payload)

    if any(value == 0 for value in filled):
        raise ValueError("Reassembly failed: gap detected in checksum-valid fragment stream")

    datagram_bytes = bytes(datagram)
    if len(datagram_bytes) < 8:
        raise ValueError("Reassembly failed: datagram too short for UDP header")

    src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", datagram_bytes[:8])
    if src_port != SIGNAL_SRC_PORT or dst_port != SIGNAL_DST_PORT:
        raise ValueError("Reassembly failed: unexpected UDP ports in reconstructed datagram")
    if udp_len < 8 or udp_len > len(datagram_bytes):
        raise ValueError("Reassembly failed: invalid UDP length in reconstructed datagram")

    zip_bytes = datagram_bytes[8:udp_len]
    if len(zip_bytes) != (udp_len - 8):
        raise ValueError("Reassembly failed: UDP payload length mismatch")

    return zip_bytes, len(ordered)


def extract_flag_from_zip_bytes(zip_bytes: bytes) -> str:
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    if "flag.txt" not in archive.namelist():
        raise ValueError("Expected flag.txt inside reconstructed zip")

    text = archive.read("flag.txt").decode("utf-8").strip()
    if not text.startswith(FLAG_PREFIX):
        raise ValueError("Recovered flag has unexpected prefix")

    match = FLAG_RE.search(text)
    if not match:
        raise ValueError("Flag pattern not found in reconstructed zip")

    return match.group(0)


def solve_pcap(pcap_path: Path, output_zip: Path) -> tuple[str, int, int]:
    zip_bytes, fragment_count = extract_signal_zip_bytes(pcap_path=pcap_path)
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    output_zip.write_bytes(zip_bytes)

    flag = extract_flag_from_zip_bytes(zip_bytes)
    return flag, len(zip_bytes), fragment_count


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solve Fragmented Whispers PCAP")
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
    parser.add_argument("--print-stats", action="store_true", help="Print reconstruction stats")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    flag, zip_size, fragment_count = solve_pcap(
        pcap_path=args.pcap.resolve(),
        output_zip=args.output_zip.resolve(),
    )
    print(flag)

    if args.print_stats:
        print(f"[stats] reconstructed_zip_bytes={zip_size}")
        print(f"[stats] validated_fragments={fragment_count}")
        print(f"[stats] output_zip={args.output_zip.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
