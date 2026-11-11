#!/usr/bin/env python3
"""
ZSCTF :: Lacquerbox -- reference solver (pure analysis, no brute force).

Intended path:
  1. Reverse the `lacq` engine. The transform over the token is a balanced
     Feistel network: pre-whiten, R rounds of (Lh, Rh) -> (Rh, Lh XOR F(Rh)),
     post-whiten. The round subkeys and the two whitening keys are derived
     from a master seed in the image by SHA-256 (the key schedule). The S-box
     and master seed are read straight from the image.
  2. The key insight: a Feistel round is invertible WITHOUT inverting its round
     function F. Given the output (Lh', Rh') of a round, the input was
         Rh = Lh'                        (new left is the old right)
         Lh = Rh' XOR F(Rh)              (so old left = new right XOR F(old right))
     So we run the whole network backwards from the embedded `expected` target,
     peeling the post-whitening, R reverse rounds, then the pre-whitening, to
     obtain the unique correct token X. No search, no guessing.
  3. (Optional) feed X to the real `lacq` binary and watch it print the flag.

  python3 solve.py --image challenge.lacq                 # recover + print token
  python3 solve.py --image challenge.lacq --bin ./lacq    # ...and win the flag
"""
import os, sys, struct, argparse, subprocess, hashlib


def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF


def parse_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"LACQ":
        raise ValueError("not a LACQ image")
    ver, L, R, seed_len = data[4], data[5], data[6], data[7]
    (flag_len,) = struct.unpack_from("<H", data, 8)
    off = 10
    sbox = data[off:off + 256]; off += 256
    master = data[off:off + seed_len]; off += seed_len
    expected = data[off:off + L]; off += L
    flag_ct = data[off:off + flag_len]; off += flag_len
    return dict(L=L, R=R, seed_len=seed_len, sbox=sbox, master=master,
                expected=expected, flag_ct=flag_ct)


# --- key schedule (recovered from the engine) ------------------------------
def kdf(master, tag, idx, outlen):
    out = b""
    j = 0
    while len(out) < outlen:
        out += hashlib.sha256(master + tag + bytes([idx]) + bytes([j])).digest()
        j += 1
    return out[:outlen]


def round_function(x, rk, sbox):
    h = len(x)
    t = [sbox[(x[i] + rk[i]) & 0xFF] for i in range(h)]
    t = [rol8(t[i], x[(i + 1) % h] & 7) for i in range(h)]
    for i in range(1, h):
        t[i] ^= t[i - 1]
    return t


def encrypt(master, sbox, L, R, block):
    """Forward Lacquer (used only to verify the recovered token)."""
    h = L // 2
    wk1 = kdf(master, b"WK", 1, L)
    wk2 = kdf(master, b"WK", 2, L)
    b = [block[i] ^ wk1[i] for i in range(L)]
    for r in range(R):
        rk = kdf(master, b"RK", r, h)
        Lh, Rh = b[:h], b[h:]
        fout = round_function(Rh, rk, sbox)
        b = Rh + [(Lh[i] ^ fout[i]) & 0xFF for i in range(h)]
    b = [b[i] ^ wk2[i] for i in range(L)]
    return bytes(b)


def decrypt(master, sbox, L, R, expected):
    """Run the Feistel network backwards -> the unique correct token."""
    h = L // 2
    wk1 = kdf(master, b"WK", 1, L)
    wk2 = kdf(master, b"WK", 2, L)

    b = [expected[i] ^ wk2[i] for i in range(L)]      # peel post-whitening
    for r in range(R - 1, -1, -1):                    # reverse round order
        rk = kdf(master, b"RK", r, h)
        newLh, newRh = b[:h], b[h:]
        Rh = newLh[:]                                 # new left was old right
        fout = round_function(Rh, rk, sbox)
        Lh = [(newRh[i] ^ fout[i]) & 0xFF for i in range(h)]
        b = Lh + Rh
    b = [b[i] ^ wk1[i] for i in range(L)]             # peel pre-whitening
    return bytes(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to the .lacq image")
    ap.add_argument("--bin", help="path to the compiled lacq engine (to win the flag)")
    args = ap.parse_args()

    im = parse_image(args.image)
    token = decrypt(im["master"], im["sbox"], im["L"], im["R"], im["expected"])

    # sanity: forward(token) must reproduce the embedded target
    check = encrypt(im["master"], im["sbox"], im["L"], im["R"], token)
    if check != im["expected"]:
        print("[-] inversion failed: encrypt(token) != expected", file=sys.stderr)
        return 1

    printable = all(32 <= c < 127 for c in token)
    print("[+] recovered license token: %s%s"
          % (token.decode("latin-1"), "" if printable else "  (non-printable)"))

    if not args.bin:
        print("[+] (no --bin given; token recovered by analysis only)")
        return 0

    engine = os.path.abspath(args.bin)
    image = os.path.abspath(args.image)
    proc = subprocess.run([engine, image], input=token + b"\n",
                          capture_output=True, timeout=30)
    out = proc.stdout.decode("latin-1", "replace").strip()
    print("[+] engine response: %s" % out)
    if out.startswith("zerosecurectf{"):
        print("[+] FLAG =", out)
        return 0
    print("[-] did not get a flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
