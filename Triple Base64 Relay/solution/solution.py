import base64
from pathlib import Path


def decode_three_layers(payload: str) -> tuple[str, str, str]:
    """Decode a Base64 payload three times and return each layer."""
    layer1 = base64.b64decode(payload).decode("utf-8")
    layer2 = base64.b64decode(layer1).decode("utf-8")
    layer3 = base64.b64decode(layer2).decode("utf-8")
    return layer1, layer2, layer3


def main() -> None:
    payload = Path("challenge.txt").read_text(encoding="utf-8").strip()
    layer1, layer2, final_flag = decode_three_layers(payload)

    print("Decode 1:", layer1)
    print("Decode 2:", layer2)
    print("Decode 3 (flag):", final_flag)


if __name__ == "__main__":
    main()
