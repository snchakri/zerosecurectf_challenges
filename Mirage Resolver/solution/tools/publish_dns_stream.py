"""Deterministic DNS packet planning and PCAP writing for ch5."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Packet, wrpcap  # type: ignore[import-untyped]

from challenge_config import (
    CAPTURE_DURATION_SECONDS,
    DECOY_FLAG_MESSAGES,
    DECOY_MISC_MESSAGES,
    DNS_CLIENT_IP,
    DNS_SERVER_IP,
    DNS_ZONE,
    EPHEMERAL_MAX,
    EPHEMERAL_MIN,
    FLAG,
    NOISE_A_PAIR_TARGET,
    NOISE_NXDOMAIN_PAIR_TARGET,
    NOISE_TXT_PAIR_TARGET,
    RESPONSE_DELAY_MAX_SECONDS,
    RESPONSE_DELAY_MIN_SECONDS,
    SEED_DEFAULT,
    SIGNAL_A_PREFIX,
    SIGNAL_CLIENT_SPORT_START,
    SIGNAL_PAIR_INTERVAL_SECONDS,
    SIGNAL_PAIR_JITTER_SECONDS,
    SIGNAL_TTL_SECONDS,
    SIGNAL_TXID_BASE,
    SIGNAL_WINDOW_START_SECONDS,
)


@dataclass(frozen=True)
class DnsPacketPlan:
    timestamp: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    dns_id: int
    qr: int
    qname: str
    qtype: str
    aa: int
    rd: int
    ra: int
    rcode: int
    answer_ipv4: str | None
    answer_txt: str | None
    ttl: int
    is_signal: bool
    channel: str


@dataclass(frozen=True)
class GenerationCounts:
    total_packets: int
    total_pairs: int
    signal_pairs: int
    noise_a_pairs: int
    noise_txt_pairs: int
    noise_nxdomain_pairs: int
    signal_packets: int
    noise_packets: int
    encoded_bytes: int
    decoy_flag_messages: int


def _normalize_zone(zone: str) -> str:
    return zone if zone.endswith(".") else f"{zone}."


def _random_label(rng: random.Random, *, length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def _signal_qname(rng: random.Random, index: int) -> str:
    zone = _normalize_zone(DNS_ZONE)
    prefix = _random_label(rng, length=9)
    return f"upd-{prefix}-{index:02d}.{zone}"


def _noise_qname(rng: random.Random, index: int) -> str:
    zone = _normalize_zone(DNS_ZONE)
    nouns = ("update", "printer", "asset", "sync", "proxy", "backup", "cache", "agent")
    token = _random_label(rng, length=6)
    return f"{rng.choice(nouns)}-{index:03d}-{token}.{zone}"


def _allocate_dns_id(rng: random.Random, used_ids: set[int]) -> int:
    while True:
        candidate = rng.randint(1, 65535)
        if candidate not in used_ids:
            used_ids.add(candidate)
            return candidate


def _signal_plans(rng: random.Random, flag_text: str) -> tuple[list[DnsPacketPlan], list[int], list[int]]:
    plans: list[DnsPacketPlan] = []
    txids: list[int] = []
    sports: list[int] = []

    for idx, ch in enumerate(flag_text):
        txid = (SIGNAL_TXID_BASE + idx) % 65536
        if txid == 0:
            txid = 1

        qname = _signal_qname(rng, idx)
        sport = SIGNAL_CLIENT_SPORT_START + idx
        if sport < EPHEMERAL_MIN or sport > EPHEMERAL_MAX:
            raise ValueError("Signal source port escaped ephemeral range")

        query_time = (
            SIGNAL_WINDOW_START_SECONDS
            + (idx * SIGNAL_PAIR_INTERVAL_SECONDS)
            + rng.uniform(-SIGNAL_PAIR_JITTER_SECONDS, SIGNAL_PAIR_JITTER_SECONDS)
        )
        query_time = max(0.001, query_time)
        response_time = query_time + rng.uniform(RESPONSE_DELAY_MIN_SECONDS, RESPONSE_DELAY_MAX_SECONDS)

        answer_ip = f"{SIGNAL_A_PREFIX}{ord(ch)}"

        plans.append(
            DnsPacketPlan(
                timestamp=query_time,
                src_ip=DNS_CLIENT_IP,
                dst_ip=DNS_SERVER_IP,
                sport=sport,
                dport=53,
                dns_id=txid,
                qr=0,
                qname=qname,
                qtype="A",
                aa=0,
                rd=1,
                ra=0,
                rcode=0,
                answer_ipv4=None,
                answer_txt=None,
                ttl=0,
                is_signal=True,
                channel="signal-query",
            )
        )

        plans.append(
            DnsPacketPlan(
                timestamp=response_time,
                src_ip=DNS_SERVER_IP,
                dst_ip=DNS_CLIENT_IP,
                sport=53,
                dport=sport,
                dns_id=txid,
                qr=1,
                qname=qname,
                qtype="A",
                aa=1,
                rd=1,
                ra=1,
                rcode=0,
                answer_ipv4=answer_ip,
                answer_txt=None,
                ttl=SIGNAL_TTL_SECONDS,
                is_signal=True,
                channel="signal-response",
            )
        )

        txids.append(txid)
        sports.append(sport)

    return plans, txids, sports


def _noise_a_plans(rng: random.Random, count: int, used_ids: set[int]) -> list[DnsPacketPlan]:
    plans: list[DnsPacketPlan] = []

    for idx in range(count):
        txid = _allocate_dns_id(rng, used_ids)
        qname = _noise_qname(rng, idx)
        sport = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)

        query_time = rng.uniform(0.15, CAPTURE_DURATION_SECONDS - 0.3)
        response_time = query_time + rng.uniform(RESPONSE_DELAY_MIN_SECONDS, RESPONSE_DELAY_MAX_SECONDS)

        # Keep noise answers in different private ranges to preserve one dominant signal discriminator.
        answer_ip = f"10.23.{rng.randint(1, 9)}.{rng.randint(2, 250)}"

        plans.append(
            DnsPacketPlan(
                timestamp=query_time,
                src_ip=DNS_CLIENT_IP,
                dst_ip=DNS_SERVER_IP,
                sport=sport,
                dport=53,
                dns_id=txid,
                qr=0,
                qname=qname,
                qtype="A",
                aa=0,
                rd=1,
                ra=0,
                rcode=0,
                answer_ipv4=None,
                answer_txt=None,
                ttl=0,
                is_signal=False,
                channel="noise-a-query",
            )
        )

        plans.append(
            DnsPacketPlan(
                timestamp=response_time,
                src_ip=DNS_SERVER_IP,
                dst_ip=DNS_CLIENT_IP,
                sport=53,
                dport=sport,
                dns_id=txid,
                qr=1,
                qname=qname,
                qtype="A",
                aa=1,
                rd=1,
                ra=1,
                rcode=0,
                answer_ipv4=answer_ip,
                answer_txt=None,
                ttl=rng.choice((60, 120, 300, 900)),
                is_signal=False,
                channel="noise-a-response",
            )
        )

    return plans


def _noise_txt_plans(rng: random.Random, count: int, used_ids: set[int]) -> tuple[list[DnsPacketPlan], int]:
    plans: list[DnsPacketPlan] = []
    decoy_count = 0

    txt_messages = list(DECOY_FLAG_MESSAGES + DECOY_MISC_MESSAGES)
    for idx in range(count):
        txid = _allocate_dns_id(rng, used_ids)
        qname = _noise_qname(rng, 900 + idx)
        sport = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        txt_payload = txt_messages[idx % len(txt_messages)]

        if txt_payload.startswith("ZeroSecure_CTF{"):
            decoy_count += 1

        query_time = rng.uniform(0.1, CAPTURE_DURATION_SECONDS - 0.4)
        response_time = query_time + rng.uniform(RESPONSE_DELAY_MIN_SECONDS, RESPONSE_DELAY_MAX_SECONDS)

        plans.append(
            DnsPacketPlan(
                timestamp=query_time,
                src_ip=DNS_CLIENT_IP,
                dst_ip=DNS_SERVER_IP,
                sport=sport,
                dport=53,
                dns_id=txid,
                qr=0,
                qname=qname,
                qtype="TXT",
                aa=0,
                rd=1,
                ra=0,
                rcode=0,
                answer_ipv4=None,
                answer_txt=None,
                ttl=0,
                is_signal=False,
                channel="noise-txt-query",
            )
        )

        plans.append(
            DnsPacketPlan(
                timestamp=response_time,
                src_ip=DNS_SERVER_IP,
                dst_ip=DNS_CLIENT_IP,
                sport=53,
                dport=sport,
                dns_id=txid,
                qr=1,
                qname=qname,
                qtype="TXT",
                aa=1,
                rd=1,
                ra=1,
                rcode=0,
                answer_ipv4=None,
                answer_txt=txt_payload,
                ttl=rng.choice((30, 60, 90, 120)),
                is_signal=False,
                channel="noise-txt-response",
            )
        )

    return plans, decoy_count


def _noise_nxdomain_plans(rng: random.Random, count: int, used_ids: set[int]) -> list[DnsPacketPlan]:
    plans: list[DnsPacketPlan] = []

    zone = _normalize_zone(DNS_ZONE)
    for idx in range(count):
        txid = _allocate_dns_id(rng, used_ids)
        sport = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        qname = f"{_random_label(rng, length=10)}-{idx:02d}.invalid.{zone}"

        query_time = rng.uniform(0.3, CAPTURE_DURATION_SECONDS - 0.25)
        response_time = query_time + rng.uniform(RESPONSE_DELAY_MIN_SECONDS, RESPONSE_DELAY_MAX_SECONDS)

        plans.append(
            DnsPacketPlan(
                timestamp=query_time,
                src_ip=DNS_CLIENT_IP,
                dst_ip=DNS_SERVER_IP,
                sport=sport,
                dport=53,
                dns_id=txid,
                qr=0,
                qname=qname,
                qtype="A",
                aa=0,
                rd=1,
                ra=0,
                rcode=0,
                answer_ipv4=None,
                answer_txt=None,
                ttl=0,
                is_signal=False,
                channel="noise-nxdomain-query",
            )
        )

        plans.append(
            DnsPacketPlan(
                timestamp=response_time,
                src_ip=DNS_SERVER_IP,
                dst_ip=DNS_CLIENT_IP,
                sport=53,
                dport=sport,
                dns_id=txid,
                qr=1,
                qname=qname,
                qtype="A",
                aa=1,
                rd=1,
                ra=1,
                rcode=3,
                answer_ipv4=None,
                answer_txt=None,
                ttl=0,
                is_signal=False,
                channel="noise-nxdomain-response",
            )
        )

    return plans


def build_generation_plan(seed: int = SEED_DEFAULT, flag_text: str = FLAG) -> tuple[list[DnsPacketPlan], GenerationCounts]:
    """Build deterministic DNS packet plans for challenge artifact generation."""

    rng = random.Random(seed)
    all_plans: list[DnsPacketPlan] = []

    signal_plans, signal_txids, _ = _signal_plans(rng=rng, flag_text=flag_text)
    used_ids = set(signal_txids)

    noise_a = _noise_a_plans(rng=rng, count=NOISE_A_PAIR_TARGET, used_ids=used_ids)
    noise_txt, decoy_count = _noise_txt_plans(rng=rng, count=NOISE_TXT_PAIR_TARGET, used_ids=used_ids)
    noise_nx = _noise_nxdomain_plans(rng=rng, count=NOISE_NXDOMAIN_PAIR_TARGET, used_ids=used_ids)

    all_plans.extend(signal_plans)
    all_plans.extend(noise_a)
    all_plans.extend(noise_txt)
    all_plans.extend(noise_nx)

    all_plans.sort(key=lambda plan: plan.timestamp)

    signal_pairs = sum(1 for p in all_plans if p.is_signal and p.qr == 0)
    noise_a_pairs = sum(1 for p in all_plans if (not p.is_signal) and p.channel == "noise-a-query")
    noise_txt_pairs = sum(1 for p in all_plans if (not p.is_signal) and p.channel == "noise-txt-query")
    noise_nxdomain_pairs = sum(1 for p in all_plans if (not p.is_signal) and p.channel == "noise-nxdomain-query")

    counts = GenerationCounts(
        total_packets=len(all_plans),
        total_pairs=len(all_plans) // 2,
        signal_pairs=signal_pairs,
        noise_a_pairs=noise_a_pairs,
        noise_txt_pairs=noise_txt_pairs,
        noise_nxdomain_pairs=noise_nxdomain_pairs,
        signal_packets=signal_pairs * 2,
        noise_packets=len(all_plans) - (signal_pairs * 2),
        encoded_bytes=len(flag_text),
        decoy_flag_messages=decoy_count,
    )

    return all_plans, counts


def iter_signal_queries(packet_plans: list[DnsPacketPlan]) -> list[DnsPacketPlan]:
    return [plan for plan in packet_plans if plan.is_signal and plan.qr == 0]


def iter_signal_responses(packet_plans: list[DnsPacketPlan]) -> list[DnsPacketPlan]:
    return [plan for plan in packet_plans if plan.is_signal and plan.qr == 1]


def _build_dns_layer(plan: DnsPacketPlan) -> DNS:
    qd = DNSQR(qname=plan.qname, qtype=plan.qtype)

    if plan.qr == 0:
        return DNS(
            id=plan.dns_id,
            qr=0,
            opcode=0,
            rd=plan.rd,
            qd=qd,
        )

    if plan.qtype == "A" and plan.answer_ipv4 is not None:
        return DNS(
            id=plan.dns_id,
            qr=1,
            opcode=0,
            aa=plan.aa,
            rd=plan.rd,
            ra=plan.ra,
            rcode=plan.rcode,
            qd=qd,
            an=DNSRR(rrname=plan.qname, type="A", ttl=plan.ttl, rdata=plan.answer_ipv4),
        )

    if plan.qtype == "TXT" and plan.answer_txt is not None:
        return DNS(
            id=plan.dns_id,
            qr=1,
            opcode=0,
            aa=plan.aa,
            rd=plan.rd,
            ra=plan.ra,
            rcode=plan.rcode,
            qd=qd,
            an=DNSRR(rrname=plan.qname, type="TXT", ttl=plan.ttl, rdata=plan.answer_txt),
        )

    return DNS(
        id=plan.dns_id,
        qr=1,
        opcode=0,
        aa=plan.aa,
        rd=plan.rd,
        ra=plan.ra,
        rcode=plan.rcode,
        qd=qd,
    )


def to_scapy_packet(plan: DnsPacketPlan) -> Packet:
    dns_layer = _build_dns_layer(plan)
    packet = IP(src=plan.src_ip, dst=plan.dst_ip, ttl=64) / UDP(sport=plan.sport, dport=plan.dport) / dns_layer
    packet.time = float(plan.timestamp)
    return packet


def write_pcap(packet_plans: list[DnsPacketPlan], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = [to_scapy_packet(plan) for plan in sorted(packet_plans, key=lambda item: item.timestamp)]
    wrpcap(str(output_path), packets)


__all__ = [
    "DnsPacketPlan",
    "GenerationCounts",
    "build_generation_plan",
    "iter_signal_queries",
    "iter_signal_responses",
    "write_pcap",
]
