from pathlib import Path


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BACON_DECODE: dict[str, str] = {
    format(index, "05b").replace("0", "A").replace("1", "B"): letter
    for index, letter in enumerate(ALPHABET)
}


def extract_ab_stream(text: str) -> str:
    """Extract a Baconian A/B stream from letter case only."""
    stream: list[str] = []
    for ch in text:
        if ch.isalpha():
            stream.append("A" if ch.isupper() else "B")
    return "".join(stream)


def decode_baconian(stream: str) -> str:
    """Decode a 5-symbol Baconian stream into uppercase plaintext."""
    if len(stream) % 5 != 0:
        raise ValueError("Symbol stream length must be divisible by 5.")

    plaintext: list[str] = []
    for index in range(0, len(stream), 5):
        group = stream[index : index + 5]
        plaintext.append(BACON_DECODE[group])
    return "".join(plaintext)


def build_flag(decoded_plaintext: str) -> str:
    """Convert decoded plaintext into final flag format."""
    return f"ZeroSecure_CTF{{{decoded_plaintext.replace('X', '_')}}}"


def main() -> None:
    payload_path = Path(__file__).with_name("challenge.txt")
    payload = payload_path.read_text(encoding="utf-8")

    stream = extract_ab_stream(payload)
    decoded_plaintext = decode_baconian(stream)
    final_flag = build_flag(decoded_plaintext)

    print("Letters extracted:", len(stream))
    print("First 10 groups:", " ".join(stream[i : i + 5] for i in range(0, min(50, len(stream)), 5)))
    print("Decoded plaintext:", decoded_plaintext)
    print("Final flag:", final_flag)


if __name__ == "__main__":
    main()
