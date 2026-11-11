#!/usr/bin/env python3
"""
DEAD HAND - build script  (REAL challenge, flag = ZeroSecure{...}).

Two transmissions were encrypted with the SAME one-time pad (pad reuse). That
is the whole vulnerability. XORing the two ciphertexts cancels the pad:

        C1 ^ C2 == P1 ^ P2

Crib-drag the known flag prefix "ZeroSecure{" across C1^C2 to line up the
plaintexts, then extend the cribs (guessing English words) until P1 falls out.
The flag lives in P1.

Flag: ZeroSecure{p4d_r3us3_br34ks_0tp}
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

FLAG = "ZeroSecure{p4d_r3us3_br34ks_0tp}"

# The two real plaintexts, encrypted under one reused pad. The flag sits in P1.
P1 = (f"ALPHA to BRAVO: archive the launch authorization as {FLAG} and stand by."
      ).encode()
P2 = ("BRAVO to ALPHA: copy your last, logging the authorization now, all quiet."
      ).encode()


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    os.makedirs(DIST, exist_ok=True)

    L = max(len(P1), len(P2))
    p1 = P1.ljust(L, b" ")
    p2 = P2.ljust(L, b" ")

    # one reused random pad
    pad = os.urandom(L)
    c1 = xor(p1, pad)
    c2 = xor(p2, pad)

    with open(os.path.join(DIST, "transmission_alpha.txt"), "w", newline="\n") as f:
        f.write(c1.hex() + "\n")
    with open(os.path.join(DIST, "transmission_bravo.txt"), "w", newline="\n") as f:
        f.write(c2.hex() + "\n")

    briefing = """\
=============================================================
  PROJECT DEAD HAND  //  INTERCEPT BRIEFING  //  EYES ONLY
=============================================================

Two encrypted transmissions, ALPHA and BRAVO, were pulled off
the silo's buried landline on the same night (see the two
transmission_*.txt files, hex-encoded).

The station's cipher used a "single-use" key tape. Discipline
on the final night was... not what it should have been.

Recover the launch authorization.
"""
    with open(os.path.join(DIST, "briefing.txt"), "w", newline="\n") as f:
        f.write(briefing)

    # --- self-verification ---------------------------------------------------
    # 1) pad reuse holds: C1 ^ C2 cancels the pad
    assert xor(c1, c2) == xor(p1, p2), "pad-reuse relation broken"
    # 2) flag is only recoverable via the plaintext, never in the ciphertext
    assert FLAG.encode() not in c1 and FLAG.encode() not in c2, "flag leaked in ciphertext"
    # 3) simulate the intended crib-drag: slide the known flag prefix over C1^C2;
    #    at the right offset it must reveal readable English from the OTHER message.
    x = xor(c1, c2)
    crib = b"ZeroSecure{"
    hit = None
    for i in range(len(x) - len(crib) + 1):
        other = xor(x[i:i + len(crib)], crib)
        if all(32 <= ch < 127 for ch in other) and other == p2[i:i + len(crib)]:
            hit = (i, other)
            break
    assert hit is not None, "crib-drag of the flag prefix did not line up"
    # 4) and recovering P1 from P2 (known-plaintext) yields the flag
    recovered_p1 = xor(x, p2)
    assert FLAG.encode() in recovered_p1, "flag not recoverable via crib-drag"

    print("[01 DEAD HAND] build OK  (flag =", FLAG + ")")
    print("  crib 'ZeroSecure{' aligns at offset", hit[0],
          "->", hit[1].decode())
    print("  C1/C2 len:", L)


if __name__ == "__main__":
    main()
