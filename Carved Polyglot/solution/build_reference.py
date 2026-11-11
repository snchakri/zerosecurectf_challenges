#!/usr/bin/env python3
"""
CARVED POLYGLOT - build script.

dist/bunker_photo.png is a PNG with a full ZIP archive appended (a polyglot):
  * image viewers / PIL see a valid PNG (trailing bytes ignored)
  * zip tools find the EOCD at the end and open the archive

The appended ZIP contains:
  * carved_note.txt     -> the BAIT (found by anyone who carves/unzips)
  * secret.zip          -> a ZipCrypto archive, weak password 'trustno1',
                           holding classified.txt -> the EARNED-FAKE
  * archive comment     -> the EGG

Decoy strings (LOCKED):
  bait        : DOOM{c4rv3d_r1ght_0ut}
  earned-fake : DOOM{z1p_cr4ck3d_g00d_j0b}
  egg         : "sealed by the Ministry of Empty Promises. contents: decoys only."
"""
import io
import os
import zipfile

from PIL import Image

from zipcrypto import make_encrypted_zip

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

BAIT = "DOOM{c4rv3d_r1ght_0ut}"
EARNED_FAKE = "DOOM{z1p_cr4ck3d_g00d_j0b}"
EGG = "sealed by the Ministry of Empty Promises. contents: decoys only."
PASSWORD = "trustno1"   # weak, present in common wordlists (rockyou)


def make_png() -> bytes:
    img = Image.new("RGB", (160, 90), (18, 20, 24))
    # a few "bunker" pixels so it isn't a flat image
    for x in range(160):
        img.putpixel((x, 45), (60, 70, 60))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main():
    os.makedirs(DIST, exist_ok=True)

    # inner encrypted zip -> earned-fake
    classified = (
        "CLASSIFIED // VAULT MANIFEST\n"
        f"{EARNED_FAKE}\n"
        "(cross-referenced against the master list: see archive note.)\n"
    ).encode()
    secret_zip = make_encrypted_zip("classified.txt", classified, PASSWORD)

    # outer (unencrypted) zip: bait note + the encrypted inner zip + egg comment
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "carved_note.txt",
            "recovered from the appended archive:\n"
            f"{BAIT}\n"
            "the rest of the vault is in secret.zip (locked).\n",
        )
        z.writestr("secret.zip", secret_zip)
        z.comment = EGG.encode()
    outer_zip = outer.getvalue()

    png = make_png()
    polyglot = png + outer_zip
    out = os.path.join(DIST, "bunker_photo.png")
    with open(out, "wb") as f:
        f.write(polyglot)

    # --- self-verification ---------------------------------------------------
    # 1) still a valid PNG
    Image.open(io.BytesIO(polyglot)).verify()
    # 2) still a valid ZIP (EOCD found despite PNG prefix)
    with zipfile.ZipFile(io.BytesIO(polyglot)) as z:
        assert z.comment.decode() == EGG, "egg missing from zip comment"
        note = z.read("carved_note.txt").decode()
        assert BAIT in note, "bait missing from carved note"
        inner = z.read("secret.zip")
    # 3) inner encrypted zip opens only with the password
    with zipfile.ZipFile(io.BytesIO(inner)) as zi:
        try:
            zi.read("classified.txt")  # no pwd -> must fail
            raise AssertionError("inner zip was not encrypted")
        except RuntimeError:
            pass
        clear = zi.read("classified.txt", pwd=PASSWORD.encode()).decode()
        assert EARNED_FAKE in clear, "earned-fake missing from inner zip"

    print("[09 CARVED POLYGLOT] build OK")
    print("  png bytes:", len(png), "| total polyglot bytes:", len(polyglot))
    print("  inner zip password:", PASSWORD)


if __name__ == "__main__":
    main()
