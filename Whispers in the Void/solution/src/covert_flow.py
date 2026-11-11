from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Sequence, Tuple

from scapy.all import IP, TCP, Raw, PcapWriter

from src.challenge_config import ChallengeConfig


@dataclass(frozen=True)
class TimingSchedule:
    deltas_us: List[int]
    absolute_us: List[int]


def key_to_bits(key: bytes) -> List[int]:
    bits: List[int] = []
    for byte in key:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    if len(bits) != 256:
        raise ValueError("AES-256 key must be exactly 256 bits")
    return bits


def build_timing_schedule(
    packet_count: int,
    key_bits: Sequence[int],
    base_delay_us: int,
    quantum_delay_us: int,
    jitter_us: int,
    seed: int,
) -> TimingSchedule:
    rng = random.Random(seed)
    deltas_us: List[int] = []
    absolute_us: List[int] = []

    t_us = 0
    for i in range(packet_count):
        bit = key_bits[i % 256]
        jitter = rng.randint(-jitter_us, jitter_us)
        delta = base_delay_us + (bit * quantum_delay_us) + jitter
        delta = max(1000, delta)
        t_us += delta
        deltas_us.append(delta)
        absolute_us.append(t_us)
    return TimingSchedule(deltas_us=deltas_us, absolute_us=absolute_us)


def build_covert_pcap(
    png_bits: Sequence[int],
    key_bits: Sequence[int],
    config: ChallengeConfig,
    seed: int,
    output_pcap_path: str,
) -> TimingSchedule:
    schedule = build_timing_schedule(
        packet_count=len(png_bits),
        key_bits=key_bits,
        base_delay_us=config.base_delay_us,
        quantum_delay_us=config.quantum_delay_us,
        jitter_us=config.jitter_us,
        seed=seed,
    )

    writer = PcapWriter(output_pcap_path, sync=True)
    rng = random.Random(seed ^ 0x5A5A)

    client_seq = 100000
    server_seq = 200000

    syn = IP(src=config.client_ip, dst=config.server_ip) / TCP(
        sport=config.client_port,
        dport=config.server_port,
        flags="S",
        seq=client_seq,
    )
    syn.time = 0.000001
    writer.write(syn)

    syn_ack = IP(src=config.server_ip, dst=config.client_ip) / TCP(
        sport=config.server_port,
        dport=config.client_port,
        flags="SA",
        seq=server_seq,
        ack=client_seq + 1,
    )
    syn_ack.time = 0.002001
    writer.write(syn_ack)

    ack = IP(src=config.client_ip, dst=config.server_ip) / TCP(
        sport=config.client_port,
        dport=config.server_port,
        flags="A",
        seq=client_seq + 1,
        ack=server_seq + 1,
    )
    ack.time = 0.003001
    writer.write(ack)

    seq = client_seq + 1
    ack_no = server_seq + 1

    for i, bit in enumerate(png_bits):
        payload = b"0" if bit == 0 else b"1"
        pkt = IP(src=config.client_ip, dst=config.server_ip) / TCP(
            sport=config.client_port,
            dport=config.server_port,
            flags="PA",
            seq=seq,
            ack=ack_no,
        ) / Raw(payload)

        # Timing guardrail: use integer microseconds until this exact line.
        pkt.time = schedule.absolute_us[i] / 1_000_000.0
        writer.write(pkt)

        # Keep sequence progression realistic to avoid retransmission artifacts.
        seq += max(1, len(payload))

    # Add harmless background traffic to preserve global packet-budget realism.
    current_packets = 3 + len(png_bits)
    noise_packets = max(0, config.total_packets_target - current_packets - 3)
    noise_time_us = (schedule.absolute_us[-1] + 5000) if schedule.absolute_us else 7000
    for i in range(noise_packets):
        src = f"172.16.{rng.randint(1, 6)}.{rng.randint(2, 250)}"
        dst = f"172.31.{rng.randint(1, 6)}.{rng.randint(2, 250)}"
        sport = rng.randint(1025, 65530)
        dport = rng.choice((80, 443, 8080, 53))

        # Mix ACK and tiny payload packets to look routine.
        if i % 5 == 0:
            pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=1000 + i, ack=500 + i)
        else:
            pkt = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA", seq=1000 + i, ack=500 + i)
                / Raw(rng.choice((b"ping", b"ok", b"42", b"keepalive")))
            )

        noise_time_us += rng.randint(450, 2500)
        pkt.time = noise_time_us / 1_000_000.0
        writer.write(pkt)

    decoy_start = schedule.absolute_us[-1] + 18000 if schedule.absolute_us else 20000
    for i, msg in enumerate((b"DEAD END", b"WRONG PATH", b"GO DEEPER")):
        decoy_pkt = IP(src=config.server_ip, dst=config.client_ip) / TCP(
            sport=config.server_port,
            dport=config.client_port,
            flags="PA",
            seq=server_seq + 1 + i,
            ack=seq,
        ) / Raw(msg)
        decoy_pkt.time = (decoy_start + (i * 5000)) / 1_000_000.0
        writer.write(decoy_pkt)

    writer.close()
    return schedule


def recover_payload_bits_from_packets(
    packets: Sequence,
    config: ChallengeConfig,
) -> Tuple[List[int], List[int]]:
    bits: List[int] = []
    times_us: List[int] = []

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if ip.src != config.client_ip or ip.dst != config.server_ip:
            continue
        if tcp.sport != config.client_port or tcp.dport != config.server_port:
            continue
        if not pkt.haslayer(Raw):
            continue

        raw_value = bytes(pkt[Raw].load)
        if raw_value not in (b"0", b"1"):
            continue

        bits.append(0 if raw_value == b"0" else 1)
        times_us.append(int(round(float(pkt.time) * 1_000_000)))

    return bits, times_us
