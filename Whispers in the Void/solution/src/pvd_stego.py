from __future__ import annotations

from typing import Iterable, List, Tuple

from PIL import Image


def bytes_to_bits(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    bit_list = list(bits)
    if len(bit_list) % 8 != 0:
        raise ValueError("bit length must be divisible by 8")

    out = bytearray()
    for i in range(0, len(bit_list), 8):
        value = 0
        for b in bit_list[i : i + 8]:
            value = (value << 1) | (b & 1)
        out.append(value)
    return bytes(out)


def build_cover_pixels(width: int, height: int, seed: int) -> List[int]:
    pixels: List[int] = []
    for y in range(height):
        for x in range(width):
            # Large flat zones keep PNG highly compressible after limited stego edits.
            block_y = y // 12
            block_x = x // 12
            base = 92 + (block_y * 3) + (block_x * 2)
            noise = 1 if ((x * 7 + y * 11 + seed) % 23 == 0) else 0
            pixels.append(max(0, min(255, base + noise)))
    return pixels


def _apply_parity_with_clamp(p0: int, p1: int, want_bit: int) -> Tuple[int, int]:
    diff = abs(p0 - p1)
    if diff % 2 == want_bit:
        return p0, p1

    if p1 == 255:
        p1 = 254
    elif p1 == 0:
        p1 = 1
    else:
        p1 += 1
    return p0, p1


def embed_payload_pvd(payload: bytes, width: int, height: int, seed: int) -> Image.Image:
    # Prefix payload with 2-byte length so extraction is deterministic.
    framed = len(payload).to_bytes(2, "big") + payload
    bits = bytes_to_bits(framed)

    pixels = build_cover_pixels(width, height, seed)
    capacity_bits = (width * height) // 2
    if len(bits) > capacity_bits:
        raise ValueError(f"payload too large: {len(bits)} bits > {capacity_bits} bits")

    out = pixels[:]
    for pair_index in range(capacity_bits):
        i0 = pair_index * 2
        i1 = i0 + 1
        bit = bits[pair_index] if pair_index < len(bits) else abs(out[i0] - out[i1]) % 2
        p0, p1 = _apply_parity_with_clamp(out[i0], out[i1], bit)
        out[i0], out[i1] = p0, p1

    image = Image.new("L", (width, height))
    image.putdata(out)
    return image


def extract_payload_pvd(image: Image.Image) -> bytes:
    if image.mode != "L":
        image = image.convert("L")

    pixels = list(image.tobytes())
    capacity_bits = len(pixels) // 2
    bits: List[int] = []

    for pair_index in range(capacity_bits):
        i0 = pair_index * 2
        i1 = i0 + 1
        bits.append(abs(pixels[i0] - pixels[i1]) % 2)

    length = int.from_bytes(bits_to_bytes(bits[:16]), "big")
    payload_bits = bits[16 : 16 + length * 8]
    return bits_to_bytes(payload_bits)
