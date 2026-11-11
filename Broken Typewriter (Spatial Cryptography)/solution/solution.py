from pathlib import Path

# Reverse of the challenge rule: right-shifted letters are mapped back left.
LEFT_NEIGHBOR = {
    "w": "q",
    "e": "w",
    "r": "e",
    "t": "r",
    "y": "t",
    "u": "y",
    "i": "u",
    "o": "i",
    "p": "o",
    "s": "a",
    "d": "s",
    "f": "d",
    "g": "f",
    "h": "g",
    "j": "h",
    "k": "j",
    "l": "k",
    "x": "z",
    "c": "x",
    "v": "c",
    "b": "v",
    "n": "b",
    "m": "n",
}


def decode_broken_typewriter(ciphertext: str) -> str:
    """Decode text typed one key to the right on QWERTY."""
    decoded = []
    for ch in ciphertext:
        lower = ch.lower()
        if lower in LEFT_NEIGHBOR:
            plain = LEFT_NEIGHBOR[lower]
            decoded.append(plain.upper() if ch.isupper() else plain)
        else:
            decoded.append(ch)
    return "".join(decoded)


def main() -> None:
    payload_path = Path(__file__).with_name("challenge.txt")
    payload = payload_path.read_text(encoding="utf-8").strip()
    final_flag = decode_broken_typewriter(payload)

    print("Ciphertext:", payload)
    print("Decoded flag:", final_flag)


if __name__ == "__main__":
    main()
