from __future__ import annotations

import io
from collections import Counter
from statistics import mean

from Crypto.Cipher import AES
from PIL import Image
from scapy.all import IP, TCP, Raw, rdpcap


def print_section(title: str) -> None:
    edge = "=" * max(20, len(title) + 6)
    print(edge)
    print(f"  {title}")
    print(edge)


def bytes_from_bits(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be divisible by 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for b in bits[i : i + 8]:
            value = (value << 1) | (b & 1)
        out.append(value)
    return bytes(out)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty plaintext")

    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid padding value")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding bytes")
    return data[:-pad]


def find_best_bit_flow(packets) -> tuple[tuple[str, str, int, int], int]:
    flow_count = Counter()
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        raw_data = bytes(pkt[Raw].load)
        if raw_data not in (b"0", b"1"):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        key = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
        flow_count[key] += 1

    if not flow_count:
        raise RuntimeError("No candidate flow with bit-like payload found")

    return flow_count.most_common(1)[0]


def extract_png_bits_and_times(packets, flow_key: tuple[str, str, int, int]) -> tuple[list[int], list[int]]:
    bits: list[int] = []
    times_us: list[int] = []

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        current_key = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
        if current_key != flow_key:
            continue

        raw_data = bytes(pkt[Raw].load)
        if raw_data not in (b"0", b"1"):
            continue

        bits.append(0 if raw_data == b"0" else 1)
        times_us.append(int(round(float(pkt.time) * 1_000_000)))

    return bits, times_us


def extract_payload_from_png(png_bytes: bytes) -> tuple[bytes, bytes]:
    image = Image.open(io.BytesIO(png_bytes)).convert("L")
    pixels = list(image.tobytes())

    parity_bits: list[int] = []
    for i in range(0, len(pixels), 2):
        if i + 1 >= len(pixels):
            break
        parity_bits.append(abs(pixels[i] - pixels[i + 1]) % 2)

    payload_length = int.from_bytes(bytes_from_bits(parity_bits[:16]), "big")
    payload_bits = parity_bits[16 : 16 + payload_length * 8]
    payload = bytes_from_bits(payload_bits)

    if len(payload) < 17:
        raise RuntimeError("Extracted payload is too short")

    return payload[:16], payload[16:]


def recover_key_from_timing(times_us: list[int]) -> bytes:
    if len(times_us) < 256:
        raise RuntimeError("Not enough timing samples for key recovery")

    deltas = [times_us[0]] + [times_us[i] - times_us[i - 1] for i in range(1, len(times_us))]

    bucket_means: list[float] = []
    for i in range(256):
        bucket = deltas[i::256]
        bucket_means.append(mean(bucket))

    # Tiny 2-cluster approach to separate low/high timing groups.
    c0 = min(bucket_means)
    c1 = max(bucket_means)
    for _ in range(30):
        group0 = [x for x in bucket_means if abs(x - c0) <= abs(x - c1)]
        group1 = [x for x in bucket_means if abs(x - c1) < abs(x - c0)]

        new_c0 = mean(group0) if group0 else c0
        new_c1 = mean(group1) if group1 else c1
        if abs(new_c0 - c0) < 1e-9 and abs(new_c1 - c1) < 1e-9:
            break
        c0, c1 = new_c0, new_c1

    threshold = (c0 + c1) / 2.0
    key_bits = [1 if x > threshold else 0 for x in bucket_means]
    return bytes_from_bits(key_bits)


def solve(pcap_path: str) -> str:
    print_section("Step 1: Load PCAP")
    packets = rdpcap(pcap_path)
    print(f"Loaded packets: {len(packets)}")

    print_section("Step 2: Find flow carrying bit stream")
    best_flow, packet_count = find_best_bit_flow(packets)
    print(f"Candidate flow: {best_flow}")
    print(f"Bit packets in candidate flow: {packet_count}")

    print_section("Step 3: Rebuild PNG from packet bits")
    bits, times_us = extract_png_bits_and_times(packets, best_flow)
    png_bytes = bytes_from_bits(bits)
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("Candidate stream is not a PNG")
    print(f"PNG size: {len(png_bytes)} bytes")

    print_section("Step 4: Extract hidden AES payload using PVD parity")
    iv, ciphertext = extract_payload_from_png(png_bytes)
    print(f"IV bytes: {len(iv)}")
    print(f"Ciphertext bytes: {len(ciphertext)}")

    print_section("Step 5: Recover AES-256 key from timing channel")
    key = recover_key_from_timing(times_us)
    print(f"Recovered key bytes: {len(key)}")

    print_section("Step 6: Decrypt and unpad")
    plain = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
    flag = pkcs7_unpad(plain).decode("utf-8")
    print(f"Flag: {flag}")
    return flag


if __name__ == "__main__":
    solve("deliverables/participant/whispers_in_the_void.pcap")
