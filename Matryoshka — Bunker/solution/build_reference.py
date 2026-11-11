#!/usr/bin/env python3
"""
MATRYOSHKA - build script.

A nested-encoding onion. Peel order (what the solver does):

    cipher.txt
      -> base64 decode   -> reveals the BAIT + a hex blob
      -> hex decode       -> a base85 blob
      -> base85 decode    -> raw bytes that ARE a tiny ZIP file  (intermediate blob)
           * the ZIP's archive comment  = the EGG
           * the ZIP contains next_layer.txt = a REVERSED base32 string
      -> reverse          -> a base32 string
      -> base32 decode    -> the EARNED-FAKE

Anyone "just chasing text" unzips, reverses, base32-decodes and lands on the
earned-fake -- never noticing the ZIP comment that holds the doomsday egg.

Decoy strings (LOCKED):
  bait        : DOOM{0n3_l4y3r_w0nd3r}
  earned-fake : DOOM{d33p_3n0ugh_y3t}
  egg         : "87 dolls deep and still hollow. there was never a flag inside."
"""
import base64
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

BAIT = "DOOM{0n3_l4y3r_w0nd3r}"
EARNED_FAKE = "DOOM{d33p_3n0ugh_y3t}"
EGG = "87 dolls deep and still hollow. there was never a flag inside."


def main():
    os.makedirs(DIST, exist_ok=True)

    # innermost: the earned-fake plaintext
    bottom = (
        "MATRYOSHKA // BOTTOM LAYER\n"
        f"{EARNED_FAKE}\n"
        "there is nothing smaller than this. or is there?\n"
    ).encode()

    # layer 5 (solver's last two steps are reverse then base32)
    b32 = base64.b32encode(bottom)          # bytes, ascii
    reversed_b32 = b32[::-1]                 # the "reverse" step

    # the intermediate blob: a real ZIP. comment = egg, payload = reversed b32.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("next_layer.txt", reversed_b32)
        z.comment = EGG.encode()
    zip_bytes = buf.getvalue()

    # layer 3: base85 of the zip bytes
    b85 = base64.b85encode(zip_bytes)        # bytes, ascii

    # layer 2: hex of the base85 ascii
    hex_blob = b85.hex()

    # layer 1 (what base64-decoding cipher.txt reveals): bait + the hex blob
    layer1 = (
        "=== MATRYOSHKA ===\n"
        f"outer shell cracked. souvenir: {BAIT}\n"
        "keep going. decode the following (it's hex):\n\n"
        f"{hex_blob}\n"
    ).encode()

    cipher = base64.b64encode(layer1)
    with open(os.path.join(DIST, "cipher.txt"), "wb") as f:
        f.write(cipher + b"\n")

    # --- self-verification: peel it exactly like a solver would -------------
    data = open(os.path.join(DIST, "cipher.txt"), "rb").read().strip()
    step1 = base64.b64decode(data)
    assert BAIT.encode() in step1, "bait not revealed at layer 1"
    # pull the hex blob (last non-empty line)
    hx = step1.decode().strip().splitlines()[-1].strip()
    step2 = bytes.fromhex(hx)                 # -> base85 ascii
    step3 = base64.b85decode(step2)           # -> zip bytes
    assert step3[:2] == b"PK", "intermediate blob is not a ZIP"
    zbuf = io.BytesIO(step3)
    with zipfile.ZipFile(zbuf) as z:
        assert z.comment.decode() == EGG, "egg not in zip comment"
        inner = z.read("next_layer.txt")
    unreversed = inner[::-1]                   # reverse step
    final = base64.b32decode(unreversed)       # base32 step
    assert EARNED_FAKE.encode() in final, "earned-fake not at the bottom"

    print("[02 MATRYOSHKA] build OK")
    print("  cipher.txt bytes:", len(cipher))
    print("  intermediate ZIP bytes:", len(zip_bytes), "(PK header present)")


if __name__ == "__main__":
    main()
