#!/usr/bin/env python3
"""
ZSCTF :: Cogwork -- reference solver (pure analysis, no brute force).

Intended path:
  1. Recover the Cog ISA by reversing the `cog` engine (done once; the opcode
     semantics are encoded below exactly as the handlers implement them).
  2. Parse the per-instance v2 `.cog` image: S-box, position permutation, the
     straight-line program, the comparison target `expected`, the XOR-wrapped
     `flag_ct`, and the ratchet trailer (`decoy_seed` + `decoy_ct`).
  3. Every Cog opcode is a bijection on the register file, so the whole program
     is invertible. Run it BACKWARDS from `expected` -- apply each op's inverse
     in reverse program order -- to obtain the unique correct key X. (THE CRUX.)
  4. The flag is no longer printed in one shot. The engine is a GENERATOR: from
     the recovered key X derive the ratchet state path and the per-notch token
     sequence, then either
       (a) reconstruct the flag fully OFFLINE (token sequence + flag_ct), or
       (b) drive the real engine (`--bin`): feed the key line followed by the
           flag_len token lines (hex) and read the streamed flag + TRAIL.
  5. Validate the assembled flag against the strict format regex and confirm
     the TRAIL checksum matches the canonical final state.

No search, no guessing: the structure of the VM collapses the problem to a
single deterministic inversion, and the ratchet is deterministic given X.

  python3 solve.py --image challenge.cog                 # recover key + offline flag
  python3 solve.py --image challenge.cog --bin ./cog     # ...drive the real engine
"""
import os, re, sys, struct, hashlib, argparse, subprocess

# --- Cog ISA (recovered from the engine) ---
XORK, ADDK, MULK, ROLK, ADDP, SBOX, PERM, CHN, END = \
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
HAS_ARG = {XORK, ADDK, MULK, ROLK, ADDP, CHN}

# --- ratchet parameters (recovered from the engine; must match cog.c/gen.py) ---
RATCHET_LABEL = b"cogwork-ratchet-v1|"
FLAG_RE = re.compile(rb"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF


def _i4(i):
    return struct.pack("<I", i)


def parse_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"COGW":
        raise ValueError("not a COGW image")
    ver, L = data[4], data[5]
    if ver != 2:
        raise ValueError("unsupported image version %d (expected 2)" % ver)
    flag_len, prog_len = struct.unpack_from("<HH", data, 6)
    off = 10
    sbox = data[off:off + 256]; off += 256
    perm = data[off:off + L]; off += L
    program = data[off:off + prog_len]; off += prog_len
    expected = data[off:off + L]; off += L
    flag_ct = data[off:off + flag_len]; off += flag_len
    decoy_seed = data[off:off + 16]; off += 16
    decoy_ct = data[off:off + flag_len]; off += flag_len
    return dict(ver=ver, L=L, flag_len=flag_len, sbox=sbox, perm=perm,
                program=program, expected=expected, flag_ct=flag_ct,
                decoy_seed=decoy_seed, decoy_ct=decoy_ct)


def decode(program):
    """Disassemble the byte stream into (op, arg) instructions."""
    insns, pc = [], 0
    while pc < len(program):
        op = program[pc]; pc += 1
        if op == END:
            insns.append((op, None)); break
        if op in HAS_ARG:
            insns.append((op, program[pc])); pc += 1
        else:
            insns.append((op, None))
    return insns


def run_forward(insns, sbox, perm, b):
    """Forward Cog execution (used only to verify the recovered key)."""
    b = list(b); L = len(b)
    for op, k in insns:
        if op == XORK:   b = [x ^ k for x in b]
        elif op == ADDK: b = [(x + k) & 0xFF for x in b]
        elif op == MULK: b = [(x * k) & 0xFF for x in b]
        elif op == ROLK: b = [rol8(x, k) for x in b]
        elif op == ADDP: b = [(b[i] + k * (i + 1)) & 0xFF for i in range(L)]
        elif op == SBOX: b = [sbox[x] for x in b]
        elif op == PERM: b = [b[perm[i]] for i in range(L)]
        elif op == CHN:
            for i in range(1, L):
                b[i] ^= rol8(b[i - 1], k)
        elif op == END:  break
    return bytes(b)


def invert(insns, sbox, perm, expected):
    """Run the program backwards: inverse of each op, in reverse order (CRUX)."""
    L = len(expected)
    sinv = [0] * 256
    for x, y in enumerate(sbox):
        sinv[y] = x
    pinv = [0] * L
    for i, p in enumerate(perm):
        pinv[p] = i

    b = list(expected)
    for op, k in reversed(insns):
        if op == END:
            continue
        elif op == XORK:                       # self-inverse
            b = [x ^ k for x in b]
        elif op == ADDK:                       # subtract
            b = [(x - k) & 0xFF for x in b]
        elif op == MULK:                        # multiply by modular inverse
            kinv = pow(k, -1, 256)
            b = [(x * kinv) & 0xFF for x in b]
        elif op == ROLK:                        # rotate the other way
            b = [rol8(x, (8 - (k & 7)) & 7) for x in b]
        elif op == ADDP:                        # subtract position term
            b = [(b[i] - k * (i + 1)) & 0xFF for i in range(L)]
        elif op == SBOX:                        # inverse S-box
            b = [sinv[x] for x in b]
        elif op == PERM:                        # scatter back
            nb = [0] * L
            for i in range(L):
                nb[perm[i]] = b[i]
            b = nb
        elif op == CHN:                         # undo running chain, high->low
            for i in range(L - 1, 0, -1):
                b[i] ^= rol8(b[i - 1], k)
    return bytes(b)


def recover_key(im):
    """Invert the gear-chain and verify forward(key) == expected."""
    insns = decode(im["program"])
    key = invert(insns, im["sbox"], im["perm"], im["expected"])
    if run_forward(insns, im["sbox"], im["perm"], key) != im["expected"]:
        raise ValueError("inversion failed: forward(key) != expected")
    return key


def ratchet_canonical(key, n):
    """Mirror the engine's ratchet along the CORRECT path.

    Returns (tokens, emits, final_state):
      S_0     = SHA256(RATCHET_LABEL || key)
      tok_i   = SHA256(S_i || 't' || i_LE32)[:4]
      emit_i  = SHA256(S_i || tok_i || 'e' || i_LE32)[0]
      S_{i+1} = SHA256(S_i || tok_i || 'a' || i_LE32)
    """
    S = hashlib.sha256(RATCHET_LABEL + key).digest()
    toks, emits = [], []
    for i in range(n):
        i4 = _i4(i)
        tok = hashlib.sha256(S + b"t" + i4).digest()[:4]
        emit = hashlib.sha256(S + tok + b"e" + i4).digest()[0]
        toks.append(tok)
        emits.append(emit)
        S = hashlib.sha256(S + tok + b"a" + i4).digest()
    return toks, emits, S


def reconstruct_offline(im, key):
    """Assemble the flag without the engine: flag[i] = flag_ct[i] ^ emit_i."""
    toks, emits, final = ratchet_canonical(key, im["flag_len"])
    flag = bytes(c ^ e for c, e in zip(im["flag_ct"], emits))
    trail = final[:4].hex()
    return flag, toks, trail


def drive_engine(engine, image, key, toks):
    """Feed key + token hex lines to the real engine; parse flag line + TRAIL."""
    stdin = key + b"\n" + b"".join(t.hex().encode() + b"\n" for t in toks)
    proc = subprocess.run([os.path.abspath(engine), os.path.abspath(image)],
                          input=stdin, capture_output=True, timeout=30)
    out = proc.stdout
    if b"DENIED" in out:
        return None, None, out
    lines = out.split(b"\n")
    flag = lines[0] if lines else b""
    trail = None
    for ln in lines:
        if ln.startswith(b"TRAIL "):
            trail = ln.split(b" ", 1)[1].decode("latin-1").strip()
    return flag, trail, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to the .cog image")
    ap.add_argument("--bin", help="path to the compiled cog engine (to drive it)")
    args = ap.parse_args()

    im = parse_image(args.image)
    key = recover_key(im)

    printable = all(32 <= c < 127 for c in key)
    print("[+] recovered license key: %s%s"
          % (key.decode("latin-1"), "" if printable else "  (non-printable)"))

    # Always reconstruct offline first (proves the ratchet math from the key).
    off_flag, toks, off_trail = reconstruct_offline(im, key)
    off_valid = bool(FLAG_RE.match(off_flag))
    print("[+] offline-reconstructed flag: %s" % off_flag.decode("latin-1"))
    print("[+] offline TRAIL checksum: %s" % off_trail)
    if not off_valid:
        print("[-] offline flag FAILS the strict format regex", file=sys.stderr)

    if not args.bin:
        print("[+] (no --bin given; flag reconstructed by analysis only)")
        return 0 if off_valid else 1

    flag, trail, raw = drive_engine(args.bin, args.image, key, toks)
    if flag is None:
        print("[-] engine DENIED the recovered key:\n%s"
              % raw.decode("latin-1", "replace"), file=sys.stderr)
        return 1
    print("[+] engine streamed flag: %s" % flag.decode("latin-1", "replace"))
    print("[+] engine TRAIL checksum: %s" % trail)

    ok = (flag == off_flag) and (trail == off_trail) and bool(FLAG_RE.match(flag))
    if ok:
        print("[+] FLAG =", flag.decode("latin-1"))
        print("[+] (engine output matches offline reconstruction; TRAIL verified)")
        return 0
    print("[-] mismatch between engine and offline reconstruction, or bad format")
    return 1


if __name__ == "__main__":
    sys.exit(main())
