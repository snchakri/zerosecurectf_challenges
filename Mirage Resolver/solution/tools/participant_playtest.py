"""Isolated participant-perspective playtest for Mirage Resolver."""

from __future__ import annotations

import argparse
import re
import shutil
import tempfile
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, rdpcap  # type: ignore[import-untyped]

DEFAULT_PCAP_NAME = "mirage_resolver.pcap"
FLAG_RE = re.compile(r"^ZeroSecure_CTF\{[^}]+\}$")
FLAG_PREFIX = "ZeroSecure_CTF{"

DNS_CLIENT_IP = "10.23.7.44"
DNS_SERVER_IP = "10.23.7.53"
SIGNAL_A_PREFIX = "10.0.0."


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


def _recover_flag(pcap_path: Path) -> tuple[str, int]:
    packets = rdpcap(str(pcap_path))

    queries: set[tuple[int, str, int, str, str, int]] = set()
    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            continue
        ip = packet[IP]
        udp = packet[UDP]
        dns = packet[DNS]
        if int(dns.qr) != 0:
            continue

        qd = _first_question(dns)
        queries.add(
            (
                int(dns.id),
                _normalize_name(qd.qname),
                _qtype_int(qd.qtype),
                str(ip.src),
                str(ip.dst),
                int(udp.sport),
            )
        )

    if not queries:
        raise ValueError("No DNS query traffic present")

    octets: list[int] = []
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

        expected_query = (int(dns.id), qname, qtype, str(ip.dst), str(ip.src), int(udp.dport))
        if expected_query not in queries:
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

        rr = answers[0]
        if _normalize_name(rr.rrname) != qname or _qtype_int(rr.type) != 1:
            continue

        answer_ip = str(rr.rdata)
        if not answer_ip.startswith(SIGNAL_A_PREFIX):
            continue

        octet = int(answer_ip.split(".")[-1])
        if octet < 32 or octet > 126:
            continue

        octets.append(octet)

    if not octets:
        raise ValueError("No recoverable signal A records found")

    flag = "".join(chr(value) for value in octets)
    if not flag.startswith(FLAG_PREFIX):
        raise ValueError("Recovered text does not start with expected flag prefix")
    if not FLAG_RE.match(flag):
        raise ValueError("Recovered text does not match strict flag format")

    return flag, len(octets)


def run_playtest(source_dir: Path, work_dir: Path | None = None) -> tuple[str, Path]:
    if work_dir is None:
        temp_root = Path(tempfile.mkdtemp(prefix="mirage_resolver_playtest_"))
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

    print(f"[playtest] signal_a_records={signal_count}")
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
