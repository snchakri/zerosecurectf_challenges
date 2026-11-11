"""Deterministic TCP packet planning and PCAP materialization for ch4."""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, TCP, UDP, Packet, wrpcap  # type: ignore[import-untyped]

from challenge_config import (
    CAPTURE_DURATION_SECONDS,
    DNS_NOISE_FLOW_COUNT,
    EPHEMERAL_MAX,
    EPHEMERAL_MIN,
    FLAG,
    HTTP_NOISE_FLOW_COUNT,
    MISC_SYN_BURST_COUNT,
    NOISE_CLIENT_IPS,
    NOISE_PACKET_TARGET,
    NOISE_SERVER_IPS,
    PORT_OFFSET_BASE,
    RST_DELAY_MAX_SECONDS,
    RST_DELAY_MIN_SECONDS,
    SEED_DEFAULT,
    SIGNAL_ATTACKER_IP,
    SIGNAL_EPHEMERAL_START,
    SIGNAL_KNOCK_INTERVAL_SECONDS,
    SIGNAL_KNOCK_JITTER_SECONDS,
    SIGNAL_SERVER_IP,
    SIGNAL_SYN_INITIAL_SEQ,
    SIGNAL_SYN_SEQ_STEP,
    SIGNAL_WINDOW_START_SECONDS,
)


@dataclass(frozen=True)
class PacketPlan:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    ttl: int
    sport: int
    dport: int
    tcp_flags: str | None
    tcp_seq: int | None
    tcp_ack: int | None
    tcp_window: int | None
    is_signal: bool
    signal_role: str


@dataclass(frozen=True)
class GenerationCounts:
    total_packets: int
    signal_syn_packets: int
    signal_rst_packets: int
    noise_packets: int
    noise_tcp_packets: int
    noise_udp_packets: int


def _encoded_port_set(flag_text: str) -> set[int]:
    return {PORT_OFFSET_BASE + ord(ch) for ch in flag_text}


def _safe_noise_dport(rng: random.Random, forbidden: set[int]) -> int:
    options = [22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443, 9000]
    while True:
        candidate = rng.choice(options)
        if candidate not in forbidden:
            return candidate


def _signal_packet_plans(rng: random.Random, flag_text: str) -> list[PacketPlan]:
    plans: list[PacketPlan] = []

    for index, ch in enumerate(flag_text):
        sport = SIGNAL_EPHEMERAL_START + index
        if sport < EPHEMERAL_MIN or sport > EPHEMERAL_MAX:
            raise ValueError("Signal source port allocation escaped ephemeral range")

        dport = PORT_OFFSET_BASE + ord(ch)
        syn_seq = SIGNAL_SYN_INITIAL_SEQ + (index * SIGNAL_SYN_SEQ_STEP)

        syn_time = (
            SIGNAL_WINDOW_START_SECONDS
            + (index * SIGNAL_KNOCK_INTERVAL_SECONDS)
            + rng.uniform(-SIGNAL_KNOCK_JITTER_SECONDS, SIGNAL_KNOCK_JITTER_SECONDS)
        )
        syn_time = max(0.001, syn_time)

        rst_time = syn_time + rng.uniform(RST_DELAY_MIN_SECONDS, RST_DELAY_MAX_SECONDS)

        plans.append(
            PacketPlan(
                timestamp=syn_time,
                src_ip=SIGNAL_ATTACKER_IP,
                dst_ip=SIGNAL_SERVER_IP,
                protocol="tcp",
                ttl=64,
                sport=sport,
                dport=dport,
                tcp_flags="S",
                tcp_seq=syn_seq,
                tcp_ack=0,
                tcp_window=64240,
                is_signal=True,
                signal_role="syn",
            )
        )

        plans.append(
            PacketPlan(
                timestamp=rst_time,
                src_ip=SIGNAL_SERVER_IP,
                dst_ip=SIGNAL_ATTACKER_IP,
                protocol="tcp",
                ttl=63,
                sport=dport,
                dport=sport,
                tcp_flags="RA",
                tcp_seq=rng.randint(100_000, 900_000),
                tcp_ack=syn_seq + 1,
                tcp_window=0,
                is_signal=True,
                signal_role="rst",
            )
        )

    return plans


def _http_noise_plans(rng: random.Random, forbidden_ports: set[int]) -> list[PacketPlan]:
    plans: list[PacketPlan] = []

    for _ in range(HTTP_NOISE_FLOW_COUNT):
        client_ip = rng.choice(NOISE_CLIENT_IPS)
        server_ip = rng.choice(NOISE_SERVER_IPS)

        client_port = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        server_port = _safe_noise_dport(rng, forbidden_ports)
        if server_port not in (80, 443, 8080, 8443):
            server_port = rng.choice((80, 443, 8080, 8443))

        base = rng.uniform(0.2, CAPTURE_DURATION_SECONDS - 1.4)
        cseq = rng.randint(100_000, 5_000_000)
        sseq = rng.randint(100_000, 5_000_000)

        flow = [
            (0.0000, client_ip, server_ip, client_port, server_port, "S", cseq, 0, 65535),
            (0.0055, server_ip, client_ip, server_port, client_port, "SA", sseq, cseq + 1, 64240),
            (0.0105, client_ip, server_ip, client_port, server_port, "A", cseq + 1, sseq + 1, 65535),
            (0.0900, client_ip, server_ip, client_port, server_port, "A", cseq + 1, sseq + 1, 65535),
            (0.1200, server_ip, client_ip, server_port, client_port, "A", sseq + 1, cseq + 1, 64240),
            (0.1600, client_ip, server_ip, client_port, server_port, "FA", cseq + 1, sseq + 1, 65535),
            (0.1670, server_ip, client_ip, server_port, client_port, "FA", sseq + 1, cseq + 2, 64240),
            (0.1730, client_ip, server_ip, client_port, server_port, "A", cseq + 2, sseq + 2, 65535),
        ]

        for dt, src, dst, sport, dport, flags, seq, ack, window in flow:
            plans.append(
                PacketPlan(
                    timestamp=base + dt + rng.uniform(-0.0012, 0.0012),
                    src_ip=src,
                    dst_ip=dst,
                    protocol="tcp",
                    ttl=rng.choice((62, 63, 64, 127, 128)),
                    sport=sport,
                    dport=dport,
                    tcp_flags=flags,
                    tcp_seq=seq,
                    tcp_ack=ack,
                    tcp_window=window,
                    is_signal=False,
                    signal_role="",
                )
            )

    return plans


def _dns_noise_plans(rng: random.Random, forbidden_ports: set[int]) -> list[PacketPlan]:
    plans: list[PacketPlan] = []

    for _ in range(DNS_NOISE_FLOW_COUNT):
        client_ip = rng.choice(NOISE_CLIENT_IPS)
        server_ip = rng.choice(NOISE_SERVER_IPS)

        client_port = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        server_port = 53
        if server_port in forbidden_ports:
            server_port = 5353

        base = rng.uniform(0.1, CAPTURE_DURATION_SECONDS - 0.3)

        plans.append(
            PacketPlan(
                timestamp=base,
                src_ip=client_ip,
                dst_ip=server_ip,
                protocol="udp",
                ttl=rng.choice((63, 64, 128)),
                sport=client_port,
                dport=server_port,
                tcp_flags=None,
                tcp_seq=None,
                tcp_ack=None,
                tcp_window=None,
                is_signal=False,
                signal_role="",
            )
        )
        plans.append(
            PacketPlan(
                timestamp=base + rng.uniform(0.003, 0.014),
                src_ip=server_ip,
                dst_ip=client_ip,
                protocol="udp",
                ttl=rng.choice((61, 62, 64)),
                sport=server_port,
                dport=client_port,
                tcp_flags=None,
                tcp_seq=None,
                tcp_ack=None,
                tcp_window=None,
                is_signal=False,
                signal_role="",
            )
        )

    return plans


def _misc_syn_noise(rng: random.Random, forbidden_ports: set[int]) -> list[PacketPlan]:
    plans: list[PacketPlan] = []

    for _ in range(MISC_SYN_BURST_COUNT):
        src = rng.choice(NOISE_CLIENT_IPS)
        dst = rng.choice(NOISE_SERVER_IPS)
        sport = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        dport = _safe_noise_dport(rng, forbidden_ports)
        seq = rng.randint(10_000, 999_999)

        t = rng.uniform(0.2, CAPTURE_DURATION_SECONDS - 0.1)
        plans.append(
            PacketPlan(
                timestamp=t,
                src_ip=src,
                dst_ip=dst,
                protocol="tcp",
                ttl=rng.choice((63, 64, 65, 128)),
                sport=sport,
                dport=dport,
                tcp_flags="S",
                tcp_seq=seq,
                tcp_ack=0,
                tcp_window=65535,
                is_signal=False,
                signal_role="",
            )
        )

        if rng.random() < 0.55:
            flags = "RA"
            ack = seq + 1
            resp_seq = rng.randint(1_000, 90_000)
        else:
            flags = "SA"
            ack = seq + 1
            resp_seq = rng.randint(1_000, 90_000)

        plans.append(
            PacketPlan(
                timestamp=t + rng.uniform(0.001, 0.02),
                src_ip=dst,
                dst_ip=src,
                protocol="tcp",
                ttl=rng.choice((61, 62, 64)),
                sport=dport,
                dport=sport,
                tcp_flags=flags,
                tcp_seq=resp_seq,
                tcp_ack=ack,
                tcp_window=64240,
                is_signal=False,
                signal_role="",
            )
        )

    return plans


def _pad_noise_packets(rng: random.Random, target_noise_packets: int, current_noise_packets: list[PacketPlan], forbidden_ports: set[int]) -> None:
    while len(current_noise_packets) < target_noise_packets:
        src = rng.choice(NOISE_CLIENT_IPS)
        dst = rng.choice(NOISE_SERVER_IPS)
        sport = rng.randint(EPHEMERAL_MIN, EPHEMERAL_MAX)
        dport = _safe_noise_dport(rng, forbidden_ports)

        current_noise_packets.append(
            PacketPlan(
                timestamp=rng.uniform(0.01, CAPTURE_DURATION_SECONDS - 0.01),
                src_ip=src,
                dst_ip=dst,
                protocol="tcp",
                ttl=rng.choice((63, 64, 127, 128)),
                sport=sport,
                dport=dport,
                tcp_flags=rng.choice(("A", "PA", "R")),
                tcp_seq=rng.randint(100, 9_000_000),
                tcp_ack=rng.randint(0, 9_000_000),
                tcp_window=rng.choice((1024, 8192, 16384, 65535)),
                is_signal=False,
                signal_role="",
            )
        )


def build_generation_plan(seed: int = SEED_DEFAULT, flag_text: str = FLAG) -> tuple[list[PacketPlan], GenerationCounts]:
    """Build deterministic packet plans for challenge artifact generation."""

    rng = random.Random(seed)
    encoded_ports = _encoded_port_set(flag_text)

    signal_plans = _signal_packet_plans(rng=rng, flag_text=flag_text)

    noise_plans: list[PacketPlan] = []
    noise_plans.extend(_http_noise_plans(rng=rng, forbidden_ports=encoded_ports))
    noise_plans.extend(_dns_noise_plans(rng=rng, forbidden_ports=encoded_ports))
    noise_plans.extend(_misc_syn_noise(rng=rng, forbidden_ports=encoded_ports))

    _pad_noise_packets(
        rng=rng,
        target_noise_packets=NOISE_PACKET_TARGET,
        current_noise_packets=noise_plans,
        forbidden_ports=encoded_ports,
    )

    if len(noise_plans) != NOISE_PACKET_TARGET:
        raise ValueError("Noise packet plan did not reach target size")

    all_plans = signal_plans + noise_plans
    all_plans.sort(key=lambda item: item.timestamp)

    signal_syn_packets = sum(1 for plan in all_plans if plan.is_signal and plan.signal_role == "syn")
    signal_rst_packets = sum(1 for plan in all_plans if plan.is_signal and plan.signal_role == "rst")
    noise_tcp_packets = sum(1 for plan in all_plans if (not plan.is_signal) and plan.protocol == "tcp")
    noise_udp_packets = sum(1 for plan in all_plans if (not plan.is_signal) and plan.protocol == "udp")

    counts = GenerationCounts(
        total_packets=len(all_plans),
        signal_syn_packets=signal_syn_packets,
        signal_rst_packets=signal_rst_packets,
        noise_packets=len(noise_plans),
        noise_tcp_packets=noise_tcp_packets,
        noise_udp_packets=noise_udp_packets,
    )

    return all_plans, counts


def iter_signal_syn_packets(packet_plans: list[PacketPlan]) -> list[PacketPlan]:
    return [plan for plan in packet_plans if plan.is_signal and plan.signal_role == "syn"]


def iter_signal_rst_packets(packet_plans: list[PacketPlan]) -> list[PacketPlan]:
    return [plan for plan in packet_plans if plan.is_signal and plan.signal_role == "rst"]


def to_scapy_packet(plan: PacketPlan) -> Packet:
    if plan.protocol == "tcp":
        assert plan.tcp_flags is not None
        assert plan.tcp_seq is not None
        assert plan.tcp_ack is not None
        assert plan.tcp_window is not None

        packet = (
            IP(src=plan.src_ip, dst=plan.dst_ip, ttl=plan.ttl)
            / TCP(
                sport=plan.sport,
                dport=plan.dport,
                flags=plan.tcp_flags,
                seq=plan.tcp_seq,
                ack=plan.tcp_ack,
                window=plan.tcp_window,
            )
        )
    elif plan.protocol == "udp":
        packet = IP(src=plan.src_ip, dst=plan.dst_ip, ttl=plan.ttl) / UDP(sport=plan.sport, dport=plan.dport)
    else:
        raise ValueError(f"Unsupported protocol: {plan.protocol}")

    packet.time = float(plan.timestamp)
    return packet


def write_pcap(packet_plans: list[PacketPlan], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = [to_scapy_packet(plan) for plan in sorted(packet_plans, key=lambda item: item.timestamp)]
    wrpcap(str(output_path), packets)


__all__ = [
    "GenerationCounts",
    "PacketPlan",
    "build_generation_plan",
    "iter_signal_rst_packets",
    "iter_signal_syn_packets",
    "write_pcap",
]
