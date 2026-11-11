#!/usr/bin/env python3
import base64
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "polyglot_payload.dat"

KEY = "Natsuki_Subaru_Network"
FLAG = "ZeroSecure_CTF{polyglot_layers_resolve_9}"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)

    enc = xor_bytes(FLAG.encode("ascii"), KEY.encode("ascii"))
    enc_hex = enc.hex()
    enc_b64 = base64.b64encode(enc).decode("ascii")

    body = []
    body.append("#!/usr/bin/env pseudo")
    body.append("# polyglot packet artifact")
    body.append("[HTTP]")
    body.append("Host: relay.internal")
    body.append("X-Protocol: Matryoshka")
    body.append("")
    body.append("[PYTHON]")
    body.append(f"KEY = '{KEY}'")
    body.append(f"BLOB_HEX = '{enc_hex}'")
    body.append("")
    body.append("[C]")
    body.append("unsigned char nested[] = {")
    body.append(", ".join(f"0x{x:02x}" for x in enc) + "};")
    body.append("")
    body.append("[JSON]")
    body.append('{"blob_b64": "' + enc_b64 + '", "cipher": "xor"}')
    body.append("")
    body.append("[END]")

    OUT.write_text("\n".join(body) + "\n", encoding="utf-8")
    print(f"[ok] wrote {OUT}")


if __name__ == "__main__":
    main()
