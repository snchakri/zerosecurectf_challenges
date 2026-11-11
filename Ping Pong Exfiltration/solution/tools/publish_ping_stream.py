"""Deterministic ICMP packet planning and PCAP materialization for ch2."""

from __future__ import annotations

import io
import random
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scapy.all import ICMP, IP, Raw, Packet, wrpcap  # type: ignore[import-untyped]

from challenge_config import (
    CAPTURE_DURATION_SECONDS,
    DECOY_SOURCE_IPS,
    FLAG,
    MIN_DECOY_REQUESTS,
    PAYLOAD_SIZE_BYTES,
    PING_TARGET_IP,
    REPLY_DELAY_MAX_SECONDS,
    REPLY_DELAY_MIN_SECONDS,
    SEED_DEFAULT,
    SIGNAL_IDENTIFIER,
    SIGNAL_SOURCE_IP,
    TOTAL_ECHO_REQUEST_TARGET,
    WINDOWS_PING_PAYLOAD,
)


@dataclass(frozen=True)
class IcmpPacketPlan:
    timestamp: float
    src_ip: str
    dst_ip: str
    ttl: int
    icmp_type: int
    identifier: int
    sequence: int
    payload: bytes
    is_signal: bool
    is_request: bool


@dataclass(frozen=True)
class GenerationCounts:
    total_packets: int
    total_requests: int
    total_replies: int
    signal_requests: int
    decoy_requests: int
    zip_bytes: int


def build_flag_zip_bytes(flag_text: str = FLAG) -> bytes:
    """Build the hidden ZIP blob that players must reconstruct."""

    buffer = io.BytesIO()
    # Keep the archive intentionally compact so we can preserve a healthy decoy budget.
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("flag.txt", f"{flag_text}\n")
    return buffer.getvalue()


def _non_signal_identifier(rng: random.Random) -> int:
    while True:
        candidate = rng.randint(1, 0xFFFF)
        if candidate != SIGNAL_IDENTIFIER:
            return candidate


def _signal_payload(byte_value: int) -> bytes:
    return bytes([byte_value]) + WINDOWS_PING_PAYLOAD[1:]


def _signal_timestamps(count: int, duration: float, rng: random.Random) -> list[float]:
    if count <= 0:
        return []

    slot = duration / (count + 1)
    timestamps: list[float] = []
    for index in range(count):
        center = slot * (index + 1)
        jitter = rng.uniform(-slot * 0.15, slot * 0.15)
        timestamps.append(max(0.001, center + jitter))
    return timestamps


def build_generation_plan(seed: int = SEED_DEFAULT, flag_text: str = FLAG) -> tuple[list[IcmpPacketPlan], GenerationCounts, bytes]:
    """Build request/reply packet plans for the challenge artifact."""

    rng = random.Random(seed)
    zip_blob = build_flag_zip_bytes(flag_text=flag_text)
    signal_count = len(zip_blob)

    decoy_count = TOTAL_ECHO_REQUEST_TARGET - signal_count
    if decoy_count < MIN_DECOY_REQUESTS:
        raise ValueError(
            "Zip payload is too large for configured total packet budget. "
            f"signal={signal_count} requires at least {MIN_DECOY_REQUESTS} decoys"
        )

    signal_times = _signal_timestamps(signal_count, CAPTURE_DURATION_SECONDS, rng)

    request_plans: list[IcmpPacketPlan] = []

    for sequence, byte_value in enumerate(zip_blob):
        request_plans.append(
            IcmpPacketPlan(
                timestamp=signal_times[sequence],
                src_ip=SIGNAL_SOURCE_IP,
                dst_ip=PING_TARGET_IP,
                ttl=64,
                icmp_type=8,
                identifier=SIGNAL_IDENTIFIER,
                sequence=sequence,
                payload=_signal_payload(byte_value),
                is_signal=True,
                is_request=True,
            )
        )

    for _ in range(decoy_count):
        request_plans.append(
            IcmpPacketPlan(
                timestamp=rng.uniform(0.050, CAPTURE_DURATION_SECONDS),
                src_ip=rng.choice(DECOY_SOURCE_IPS),
                dst_ip=PING_TARGET_IP,
                ttl=rng.choice((63, 64, 65, 128)),
                icmp_type=8,
                identifier=_non_signal_identifier(rng),
                sequence=rng.randint(0, 0xFFFF),
                payload=WINDOWS_PING_PAYLOAD,
                is_signal=False,
                is_request=True,
            )
        )

    request_plans.sort(key=lambda plan: plan.timestamp)

    all_plans: list[IcmpPacketPlan] = []
    for request in request_plans:
        all_plans.append(request)

        all_plans.append(
            IcmpPacketPlan(
                timestamp=request.timestamp + rng.uniform(REPLY_DELAY_MIN_SECONDS, REPLY_DELAY_MAX_SECONDS),
                src_ip=request.dst_ip,
                dst_ip=request.src_ip,
                ttl=rng.choice((61, 62, 64)),
                icmp_type=0,
                identifier=request.identifier,
                sequence=request.sequence,
                payload=request.payload,
                is_signal=request.is_signal,
                is_request=False,
            )
        )

    all_plans.sort(key=lambda plan: plan.timestamp)

    counts = GenerationCounts(
        total_packets=len(all_plans),
        total_requests=len(request_plans),
        total_replies=len(request_plans),
        signal_requests=signal_count,
        decoy_requests=decoy_count,
        zip_bytes=signal_count,
    )
    return all_plans, counts, zip_blob


def iter_signal_requests(packet_plans: list[IcmpPacketPlan]) -> list[IcmpPacketPlan]:
    return [plan for plan in packet_plans if plan.is_request and plan.is_signal]


def to_scapy_packet(plan: IcmpPacketPlan) -> Packet:
    packet = (
        IP(src=plan.src_ip, dst=plan.dst_ip, ttl=plan.ttl)
        / ICMP(type=plan.icmp_type, id=plan.identifier, seq=plan.sequence)
        / Raw(load=plan.payload)
    )
    packet.time = float(plan.timestamp)
    return packet


def write_pcap(packet_plans: list[IcmpPacketPlan], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = [to_scapy_packet(plan) for plan in sorted(packet_plans, key=lambda item: item.timestamp)]
    wrpcap(str(output_path), packets)


__all__ = [
    "GenerationCounts",
    "IcmpPacketPlan",
    "build_flag_zip_bytes",
    "build_generation_plan",
    "iter_signal_requests",
    "write_pcap",
]
