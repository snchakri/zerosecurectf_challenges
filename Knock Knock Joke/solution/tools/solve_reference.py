"""Reference solver for Knock-Knock Joke."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from scapy.all import IP, TCP, rdpcap  # type: ignore[import-untyped]

from challenge_config import (
    DEFAULT_PCAP_NAME,
    EPHEMERAL_MAX,
    EPHEMERAL_MIN,
    FLAG_PREFIX,
    PORT_OFFSET_BASE,
    SIGNAL_ATTACKER_IP,
    SIGNAL_SERVER_IP,
)

FLAG_RE = re.compile(r"^ZeroSecure_CTF\{[^}]+\}$")


class SignalSyn:
    def __init__(self, *, packet_index: int, timestamp: float, sport: int, dport: int, seq: int) -> None:
        self.packet_index = packet_index
        self.timestamp = timestamp
        self.sport = sport
        self.dport = dport
        self.seq = seq


def _tcp_flags_to_str(tcp_layer: TCP) -> str:
    return str(tcp_layer.flags)


def _is_tcp_payload_empty(packet) -> bool:
    tcp_layer = packet[TCP]
    return len(bytes(tcp_layer.payload)) == 0


def _collect_signal_syns(pcap_path: Path) -> list[SignalSyn]:
    packets = rdpcap(str(pcap_path))

    rows: list[SignalSyn] = []
    for idx, packet in enumerate(packets):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        if ip.src != SIGNAL_ATTACKER_IP or ip.dst != SIGNAL_SERVER_IP:
            continue

        flags = _tcp_flags_to_str(tcp)
        if flags != "S":
            continue

        if not _is_tcp_payload_empty(packet):
            raise ValueError("Signal SYN carried TCP payload; expected header-only traffic")

        if not (EPHEMERAL_MIN <= int(tcp.sport) <= EPHEMERAL_MAX):
            raise ValueError("Signal SYN source port is outside expected ephemeral range")

        rows.append(
            SignalSyn(
                packet_index=idx,
                timestamp=float(packet.time),
                sport=int(tcp.sport),
                dport=int(tcp.dport),
                seq=int(tcp.seq),
            )
        )

    if not rows:
        raise ValueError("No signal SYN packets found using configured source/destination tuple")

    sports = [row.sport for row in rows]
    if len(set(sports)) < 2:
        raise ValueError("Signal SYN source ports appear constant; expected realistic ephemeral allocation")

    return rows


def _collect_rst_candidates(pcap_path: Path) -> list[tuple[float, int, int, int, str, str]]:
    packets = rdpcap(str(pcap_path))

    rows: list[tuple[float, int, int, int, str, str]] = []
    for packet in packets:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        if ip.src != SIGNAL_SERVER_IP or ip.dst != SIGNAL_ATTACKER_IP:
            continue

        flags = _tcp_flags_to_str(tcp)
        if flags != "RA":
            continue

        if not _is_tcp_payload_empty(packet):
            raise ValueError("Signal RST,ACK carried TCP payload; expected header-only traffic")

        rows.append((float(packet.time), int(tcp.sport), int(tcp.dport), int(tcp.ack), ip.src, ip.dst))

    return rows


def _validate_pairing(signal_syns: list[SignalSyn], rst_rows: list[tuple[float, int, int, int, str, str]]) -> None:
    used = [False for _ in rst_rows]

    for syn in signal_syns:
        matched = False
        for idx, row in enumerate(rst_rows):
            if used[idx]:
                continue

            rst_time, rst_sport, rst_dport, rst_ack, _, _ = row
            if rst_sport != syn.dport or rst_dport != syn.sport:
                continue
            if rst_ack != syn.seq + 1:
                continue
            if rst_time < syn.timestamp:
                continue
            if rst_time - syn.timestamp > 0.080:
                continue

            used[idx] = True
            matched = True
            break

        if not matched:
            raise ValueError(
                "Missing near-immediate matching RST,ACK for signal SYN "
                f"sport={syn.sport} dport={syn.dport}"
            )


def decode_flag_from_pcap(pcap_path: Path) -> str:
    signal_syns = _collect_signal_syns(pcap_path=pcap_path)
    rst_rows = _collect_rst_candidates(pcap_path=pcap_path)

    _validate_pairing(signal_syns=signal_syns, rst_rows=rst_rows)

    decoded_chars: list[str] = []
    for syn in signal_syns:
        ascii_code = syn.dport - PORT_OFFSET_BASE
        if ascii_code < 32 or ascii_code > 126:
            raise ValueError(f"Decoded ASCII value out of printable range: {ascii_code}")
        decoded_chars.append(chr(ascii_code))

    candidate = "".join(decoded_chars)
    if not candidate.startswith(FLAG_PREFIX):
        raise ValueError("Decoded text does not start with ZeroSecure_CTF{")
    if not FLAG_RE.match(candidate):
        raise ValueError("Decoded text does not match strict flag pattern")

    return candidate


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solve Knock-Knock Joke PCAP")
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "participant-deliverables" / DEFAULT_PCAP_NAME,
        help="Path to challenge PCAP",
    )
    parser.add_argument("--print-stats", action="store_true", help="Print extracted signal statistics")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    pcap_path = args.pcap.resolve()
    flag = decode_flag_from_pcap(pcap_path=pcap_path)

    print(flag)
    if args.print_stats:
        signal_syns = _collect_signal_syns(pcap_path=pcap_path)
        print(f"[stats] signal_syn_packets={len(signal_syns)}")
        print(f"[stats] first_sport={signal_syns[0].sport} last_sport={signal_syns[-1].sport}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
