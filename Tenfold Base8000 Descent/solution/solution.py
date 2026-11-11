from pathlib import Path


BASE = 8000
ALPHABET_START = 0x3400
ALPHABET = "".join(chr(ALPHABET_START + i) for i in range(BASE))
CHAR_TO_INDEX = {ch: index for index, ch in enumerate(ALPHABET)}
EXPECTED_FLAG = "ZeroSecure_CTF{caught_it_ten}"


def b8000_encode(text: str) -> str:
    """Encode UTF-8 text into a custom Base8000 payload."""
    data = text.encode("utf-8")
    remainder = len(data) % 3
    out: list[str] = [ALPHABET[remainder]]

    full_length = len(data) - remainder
    for index in range(0, full_length, 3):
        value = (data[index] << 16) | (data[index + 1] << 8) | data[index + 2]
        out.append(ALPHABET[value // BASE])
        out.append(ALPHABET[value % BASE])

    if remainder == 1:
        out.append(ALPHABET[data[-1]])
    elif remainder == 2:
        value = (data[-2] << 8) | data[-1]
        out.append(ALPHABET[value // BASE])
        out.append(ALPHABET[value % BASE])

    return "".join(out)


def b8000_decode(payload: str) -> str:
    """Decode a custom Base8000 payload back to UTF-8 text."""
    if not payload:
        raise ValueError("Payload is empty.")

    remainder = CHAR_TO_INDEX[payload[0]]
    if remainder not in (0, 1, 2):
        raise ValueError("Invalid remainder marker.")

    tail_length = len(payload) - 1
    if tail_length < remainder or (tail_length - remainder) % 2 != 0:
        raise ValueError("Invalid payload length.")

    full_pairs = (tail_length - remainder) // 2
    cursor = 1
    output = bytearray()

    for _ in range(full_pairs):
        hi = CHAR_TO_INDEX[payload[cursor]]
        lo = CHAR_TO_INDEX[payload[cursor + 1]]
        cursor += 2

        value = hi * BASE + lo
        if value > 0xFFFFFF:
            raise ValueError("Chunk value out of range.")

        output.extend(((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))

    if remainder == 1:
        output.append(CHAR_TO_INDEX[payload[cursor]])
    elif remainder == 2:
        hi = CHAR_TO_INDEX[payload[cursor]]
        lo = CHAR_TO_INDEX[payload[cursor + 1]]
        value = hi * BASE + lo
        if value > 0xFFFF:
            raise ValueError("Remainder value out of range.")
        output.extend(((value >> 8) & 0xFF, value & 0xFF))

    return output.decode("utf-8")


def decode_ten_layers(payload: str) -> list[str]:
    """Decode the payload ten times and return all decoded layers."""
    layers: list[str] = []
    current = payload
    for _ in range(10):
        current = b8000_decode(current)
        layers.append(current)
    return layers


def main() -> None:
    payload_path = Path(__file__).with_name("challenge.txt")
    payload = payload_path.read_text(encoding="utf-8").strip()

    decoded_layers = decode_ten_layers(payload)

    for round_number, layer in enumerate(decoded_layers, start=1):
        preview = layer if len(layer) <= 120 else layer[:120] + "..."
        print(f"Decode {round_number}: len={len(layer)} preview={preview}")

    final_flag = decoded_layers[-1]
    print("Final output:", final_flag)

    if final_flag == EXPECTED_FLAG:
        print("Recovered flag matches expected value.")
    else:
        print("Recovered value does not match expected flag.")


if __name__ == "__main__":
    main()
