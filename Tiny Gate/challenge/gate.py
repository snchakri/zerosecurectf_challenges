#!/usr/bin/env python3
"""
Tiny reverse challenge.

The check is intentionally short and local:
1. Reverse the candidate string.
2. Apply a small per-byte transform.
3. Compare the result against the stored byte table.
"""

TARGET = [
    170, 92, 94, 84, 76, 92, 68, 88, 85, 65,
    85, 87, 171, 168, 80, 85, 164, 112, 67, 115,
    92, 87, 161, 165, 84, 171, 90, 167, 187, 175, 81,
]


def encode(candidate: str) -> list[int]:
    data = candidate[::-1].encode("utf-8")
    out = []
    for i, byte in enumerate(data):
        out.append(((byte + i + 3) ^ 0x2A) & 0xFF)
    return out


def main() -> None:
    guess = input("Flag: ").strip()
    if encode(guess) == TARGET:
        print("Access granted.")
    else:
        print("Nope. Reverse the transform and try again.")


if __name__ == "__main__":
    main()
