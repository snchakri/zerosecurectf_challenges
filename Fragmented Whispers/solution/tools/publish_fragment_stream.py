"""Deterministic IPv4 fragmentation planner for Fragmented Whispers."""

from __future__ import annotations

import io
import random
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, UDP, Raw, Packet, wrpcap  # type: ignore[import-untyped]

from challenge_config import (
    BACKGROUND_PACKET_COUNT,
    BACKGROUND_SOURCE_IPS,
    BACKGROUND_TTL_CHOICES,
    CAPTURE_DURATION_SECONDS,
    FLAG,
    FORGED_BAD_CHECKSUM,
    FRAGMENT_CHUNK_BYTES,
    OVERLAP_DECOY_CHUNK_BYTES,
    OVERLAP_DECOY_COUNT,
    OVERLAP_DECOY_TTL_CHOICES,
    SEED_DEFAULT,
    SIGNAL_BASE_TIME,
    SIGNAL_DEST_IP,
    SIGNAL_DST_PORT,
    SIGNAL_IP_ID,
    SIGNAL_JITTER_SECONDS,
    SIGNAL_PROTO,
    SIGNAL_SOURCE_IP,
    SIGNAL_SRC_PORT,
    SIGNAL_TIME_STEP,
    SIGNAL_TTL,
)


@dataclass(frozen=True)
class FragmentPacketPlan:
    timestamp: float
    packet: Packet
    fragment_offset_bytes: int | None
    fragment_offset_units: int | None
    payload_size: int
    more_fragments: bool
    is_signal_fragment: bool
    is_overlap_decoy: bool
    is_background_noise: bool
    is_checksum_poisoned: bool


@dataclass(frozen=True)
class GenerationCounts:
    total_packets: int
    signal_fragments: int
    decoy_packets: int
    overlap_decoys: int
    invalid_checksum_decoys: int
    background_packets: int
    checksum_poisoned_decoys: int
    zip_bytes: int


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def is_ipv4_header_checksum_valid(packet: Packet) -> bool:
    if not packet.haslayer(IP):
        return False

    ip_layer = packet[IP]
    ihl = int(ip_layer.ihl) if ip_layer.ihl is not None else 5
    header = bytes(ip_layer)[: ihl * 4]
    return _internet_checksum(header) == 0


def _fragment_stream(datagram: bytes, chunk_bytes: int) -> list[tuple[int, bytes, bool]]:
    if chunk_bytes <= 0 or chunk_bytes % 8 != 0:
        raise ValueError("Fragment chunk size must be a positive multiple of 8")

    rows: list[tuple[int, bytes, bool]] = []
    for byte_offset in range(0, len(datagram), chunk_bytes):
        chunk = datagram[byte_offset : byte_offset + chunk_bytes]
        more_fragments = (byte_offset + len(chunk)) < len(datagram)
        rows.append((byte_offset, chunk, more_fragments))

    return rows


def _non_signal_ip_id(rng: random.Random) -> int:
    while True:
        candidate = rng.randint(1, 0xFFFF)
        if candidate != SIGNAL_IP_ID:
            return candidate


def _force_invalid_ipv4_checksum(packet: Packet, preferred: int) -> Packet:
    ip_layer = packet[IP]
    ip_layer.chksum = preferred & 0xFFFF

    poisoned = IP(bytes(packet))
    if is_ipv4_header_checksum_valid(poisoned):
        ip_layer.chksum = ((preferred & 0xFFFF) ^ 0xFFFF) & 0xFFFF
        poisoned = IP(bytes(packet))

    if is_ipv4_header_checksum_valid(poisoned):
        raise ValueError("Unable to forge invalid IPv4 checksum for decoy packet")

    return poisoned


def _build_signal_or_decoy_fragment(
    *,
    payload: bytes,
    byte_offset: int,
    more_fragments: bool,
    ttl: int,
    checksum_override: int | None,
) -> Packet:
    ip_layer = IP(
        src=SIGNAL_SOURCE_IP,
        dst=SIGNAL_DEST_IP,
        ttl=ttl,
        proto=SIGNAL_PROTO,
        id=SIGNAL_IP_ID,
        flags="MF" if more_fragments else 0,
        frag=byte_offset // 8,
    )
    packet = ip_layer / Raw(load=payload)

    if checksum_override is None:
        return packet

    return _force_invalid_ipv4_checksum(packet, preferred=checksum_override)


def build_flag_zip_bytes(flag_text: str = FLAG) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("flag.txt", f"{flag_text}\n")
    return buffer.getvalue()


def build_udp_datagram_bytes(payload: bytes, src_port: int, dst_port: int) -> bytes:
    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    return udp_header + payload


def build_generation_plan(
    seed: int = SEED_DEFAULT,
    flag_text: str = FLAG,
) -> tuple[list[FragmentPacketPlan], GenerationCounts, bytes]:
    rng = random.Random(seed)

    zip_blob = build_flag_zip_bytes(flag_text=flag_text)
    udp_datagram = build_udp_datagram_bytes(zip_blob, src_port=SIGNAL_SRC_PORT, dst_port=SIGNAL_DST_PORT)

    fragment_rows = _fragment_stream(udp_datagram, chunk_bytes=FRAGMENT_CHUNK_BYTES)

    signal_order = list(range(len(fragment_rows)))
    rng.shuffle(signal_order)

    plans: list[FragmentPacketPlan] = []

    for emission_rank, row_index in enumerate(signal_order):
        byte_offset, chunk, more_fragments = fragment_rows[row_index]
        packet = _build_signal_or_decoy_fragment(
            payload=chunk,
            byte_offset=byte_offset,
            more_fragments=more_fragments,
            ttl=SIGNAL_TTL,
            checksum_override=None,
        )

        timestamp = (
            SIGNAL_BASE_TIME
            + (emission_rank * SIGNAL_TIME_STEP)
            + rng.uniform(-SIGNAL_JITTER_SECONDS, SIGNAL_JITTER_SECONDS)
        )

        plans.append(
            FragmentPacketPlan(
                timestamp=max(0.001, timestamp),
                packet=packet,
                fragment_offset_bytes=byte_offset,
                fragment_offset_units=byte_offset // 8,
                payload_size=len(chunk),
                more_fragments=more_fragments,
                is_signal_fragment=True,
                is_overlap_decoy=False,
                is_background_noise=False,
                is_checksum_poisoned=False,
            )
        )

    overlap_choices = [row[0] for row in fragment_rows]
    if len(overlap_choices) > 1:
        overlap_choices = overlap_choices[1:]

    for _ in range(OVERLAP_DECOY_COUNT):
        byte_offset = rng.choice(overlap_choices)
        payload = rng.randbytes(OVERLAP_DECOY_CHUNK_BYTES)
        more_fragments = bool(rng.choice((0, 1)))

        packet = _build_signal_or_decoy_fragment(
            payload=payload,
            byte_offset=byte_offset,
            more_fragments=more_fragments,
            ttl=rng.choice(OVERLAP_DECOY_TTL_CHOICES),
            checksum_override=FORGED_BAD_CHECKSUM,
        )

        timestamp = rng.uniform(
            SIGNAL_BASE_TIME - 0.300,
            SIGNAL_BASE_TIME + (len(fragment_rows) * SIGNAL_TIME_STEP) + 0.300,
        )

        plans.append(
            FragmentPacketPlan(
                timestamp=max(0.001, timestamp),
                packet=packet,
                fragment_offset_bytes=byte_offset,
                fragment_offset_units=byte_offset // 8,
                payload_size=len(payload),
                more_fragments=more_fragments,
                is_signal_fragment=False,
                is_overlap_decoy=True,
                is_background_noise=False,
                is_checksum_poisoned=True,
            )
        )

    for _ in range(BACKGROUND_PACKET_COUNT):
        payload = rng.randbytes(rng.randint(14, 52))
        packet = (
            IP(
                src=rng.choice(BACKGROUND_SOURCE_IPS),
                dst=SIGNAL_DEST_IP,
                ttl=rng.choice(BACKGROUND_TTL_CHOICES),
                proto=SIGNAL_PROTO,
                id=_non_signal_ip_id(rng),
            )
            / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535))
            / Raw(load=payload)
        )

        plans.append(
            FragmentPacketPlan(
                timestamp=rng.uniform(0.020, CAPTURE_DURATION_SECONDS),
                packet=packet,
                fragment_offset_bytes=None,
                fragment_offset_units=None,
                payload_size=len(payload) + 8,
                more_fragments=False,
                is_signal_fragment=False,
                is_overlap_decoy=False,
                is_background_noise=True,
                is_checksum_poisoned=False,
            )
        )

    checksum_poisoned = sum(1 for plan in plans if plan.is_checksum_poisoned)
    overlap_decoys = sum(1 for plan in plans if plan.is_overlap_decoy)
    background_packets = sum(1 for plan in plans if plan.is_background_noise)
    signal_fragments = sum(1 for plan in plans if plan.is_signal_fragment)
    decoy_packets = len(plans) - signal_fragments

    counts = GenerationCounts(
        total_packets=len(plans),
        signal_fragments=signal_fragments,
        decoy_packets=decoy_packets,
        overlap_decoys=overlap_decoys,
        invalid_checksum_decoys=checksum_poisoned,
        background_packets=background_packets,
        checksum_poisoned_decoys=checksum_poisoned,
        zip_bytes=len(zip_blob),
    )

    return plans, counts, zip_blob


def iter_signal_fragments(packet_plans: list[FragmentPacketPlan]) -> list[FragmentPacketPlan]:
    return [plan for plan in packet_plans if plan.is_signal_fragment]


def write_pcap(packet_plans: list[FragmentPacketPlan], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ordered = sorted(packet_plans, key=lambda plan: plan.timestamp)
    packets: list[Packet] = []

    for plan in ordered:
        packet = plan.packet.copy()
        packet.time = float(plan.timestamp)
        packets.append(packet)

    wrpcap(str(output_path), packets)


__all__ = [
    "FragmentPacketPlan",
    "GenerationCounts",
    "build_flag_zip_bytes",
    "build_generation_plan",
    "build_udp_datagram_bytes",
    "is_ipv4_header_checksum_valid",
    "iter_signal_fragments",
    "write_pcap",
]
