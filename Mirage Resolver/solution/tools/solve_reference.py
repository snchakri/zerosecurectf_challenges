"""Reference solver for Mirage Resolver."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, rdpcap  # type: ignore[import-untyped]

from challenge_config import (
    DEFAULT_PCAP_NAME,
    DNS_CLIENT_IP,
    DNS_SERVER_IP,
    FLAG,
    FLAG_PREFIX,
    SIGNAL_A_PREFIX,
)

FLAG_RE = re.compile(r"^ZeroSecure_CTF\{[^}]+\}$")


@dataclass(frozen=True)
class QueryRow:
    dns_id: int
    qname: str
    qtype: int
    client_ip: str
    server_ip: str
    client_sport: int


def _normalize_name(name: object) -> str:
    if isinstance(name, bytes):
        text = name.decode("utf-8", errors="replace")
    else:
        text = str(name)
    text = text.strip().lower()
    if not text.endswith("."):
        text = f"{text}."
    return text


def _qtype_int(qtype: object) -> int:
    if isinstance(qtype, int):
        return qtype
    value = str(qtype).upper()
    if value == "A":
        return 1
    if value == "TXT":
        return 16
    return int(value)


def _iter_answers(dns_layer: DNS) -> list[DNSRR]:
    if int(dns_layer.ancount) <= 0:
        return []

    an_field = dns_layer.an
    if an_field is None:
        return []

    if isinstance(an_field, DNSRR):
        answers: list[DNSRR] = []
        rr = an_field
        for _ in range(int(dns_layer.ancount)):
            if not isinstance(rr, DNSRR):
                break
            answers.append(rr)
            rr = rr.payload
        return answers

    # Scapy 2.6+ exposes DNS answer/question fields as packet lists.
    packet_list = list(an_field)
    return [item for item in packet_list if isinstance(item, DNSRR)][: int(dns_layer.ancount)]


def _first_question(dns_layer: DNS) -> DNSQR:
    qd_field = dns_layer.qd
    if isinstance(qd_field, DNSQR):
        return qd_field

    packet_list = list(qd_field)
    if not packet_list or not isinstance(packet_list[0], DNSQR):
        raise ValueError("DNS question section is missing or malformed")
    return packet_list[0]


def _collect_queries(pcap_path: Path) -> set[tuple[int, str, int, str, str, int]]:
    packets = rdpcap(str(pcap_path))
    rows: set[tuple[int, str, int, str, str, int]] = set()

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            continue

        ip = packet[IP]
        udp = packet[UDP]
        dns = packet[DNS]
        if int(dns.qr) != 0:
            continue

        qd = _first_question(dns)
        qname = _normalize_name(qd.qname)
        qtype = _qtype_int(qd.qtype)

        rows.add((int(dns.id), qname, qtype, str(ip.src), str(ip.dst), int(udp.sport)))

    if not rows:
        raise ValueError("No DNS queries found in capture")

    return rows


def decode_flag_from_pcap(pcap_path: Path) -> tuple[str, int]:
    queries = _collect_queries(pcap_path)
    packets = rdpcap(str(pcap_path))

    signal_octets: list[int] = []

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            continue

        ip = packet[IP]
        udp = packet[UDP]
        dns = packet[DNS]

        if int(dns.qr) != 1:
            continue

        qd = _first_question(dns)
        qname = _normalize_name(qd.qname)
        qtype = _qtype_int(qd.qtype)

        expected_query_key = (int(dns.id), qname, qtype, str(ip.dst), str(ip.src), int(udp.dport))
        if expected_query_key not in queries:
            continue

        if str(ip.src) != DNS_SERVER_IP or str(ip.dst) != DNS_CLIENT_IP:
            continue
        if int(udp.sport) != 53:
            continue

        if int(dns.rcode) != 0 or qtype != 1:
            continue

        answers = _iter_answers(dns)
        if not answers:
            continue

        first_answer = answers[0]
        if _normalize_name(first_answer.rrname) != qname:
            continue

        if _qtype_int(first_answer.type) != 1:
            continue

        answer_ip = str(first_answer.rdata)
        if not answer_ip.startswith(SIGNAL_A_PREFIX):
            continue

        try:
            octet = int(answer_ip.split(".")[-1])
        except ValueError as exc:
            raise ValueError(f"Signal answer IP not parseable: {answer_ip}") from exc

        if octet < 32 or octet > 126:
            raise ValueError(f"Signal answer octet out of printable ASCII range: {octet}")

        signal_octets.append(octet)

    if not signal_octets:
        raise ValueError("No signal DNS A responses found using configured discriminator")

    candidate = "".join(chr(value) for value in signal_octets)
    if not candidate.startswith(FLAG_PREFIX):
        raise ValueError("Decoded candidate does not start with ZeroSecure_CTF{")
    if not FLAG_RE.match(candidate):
        raise ValueError("Decoded candidate does not match strict flag format")
    if candidate != FLAG:
        raise ValueError("Decoded candidate does not match expected true flag")

    return candidate, len(signal_octets)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Solve Mirage Resolver PCAP")
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
    flag, signal_count = decode_flag_from_pcap(pcap_path)

    print(f"TRUE FLAG: {flag}")
    if args.print_stats:
        print(f"[stats] signal_a_records={signal_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
