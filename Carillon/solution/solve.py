#!/usr/bin/env python3
"""
ZSCTF :: Carillon -- reference solver (pure analysis, no brute force, no z3).

Intended path (what a solver must do, and what this script does):

  1. Recover the ISA from the stripped engine: the flattened dispatch loop,
     the 10-byte block record, the seven register-VM opcodes, the GF(2^8)
     multiply (AES poly 0x11B), the per-block SHA-256 bytecode decryption, and
     the opaque-predicate edge selector pred(pk, c). (Done once; encoded below
     exactly as the handlers implement them.)

  2. Parse the `.car` image: header, bkey, S-box, the ENCRYPTED block table,
     entry block, and the comparison target `expected`.

  3. Decrypt + lift the flattened bytecode: decrypt each block the dispatcher
     fetches, start at `entry`, resolve pred(pk, c) to pick the LIVE successor,
     collect the instruction, stop at HALT. Decoys on the dead edges are never
     fetched on the live path and are ignored.

  4. Model the system the VM computes. The lifted program is R affine layers
     over GF(2^8) separated by bytewise S-box layers:
        state -> A_r * state (+) c_r  ;  state -> SBOX[state]
     Recover each (A_r, c_r) by SYMBOLIC affine execution of the linear section
     between two S-box layers: run it with the L state registers initialised to
     the unit affine forms and read the resulting matrix + constant off the
     state registers. (This is the step that makes it a *system* rather than a
     per-byte compare: the matrix multiply is not invertible instruction by
     instruction -- you must assemble the matrix and invert it.)

  5. Invert the system. Peel the rounds from `expected` backwards: undo the
     S-box with its inverse table, then solve A_r * in = (out (+) c_r) for `in`
     via the GF(2^8) matrix inverse (hand-rolled Gauss-Jordan). After R rounds
     you have the unique key X.

  6. (Optional) feed X to the real `carillon` engine and watch it print the flag.

No search, no guessing. Resolving the key-independent opaque predicates
linearises the flattened graph to one straight-line program; recognising the
S-box layers segments it into affine blocks; field linear algebra inverts it.

  python3 solve.py --image challenge.car                 # recover + print key
  python3 solve.py --image challenge.car --bin ./carillon  # ...and win the flag
"""
import os, sys, re, struct, hashlib, argparse, subprocess

# --- Carillon ISA (recovered from the engine) ---
HALT, CLR, MOV, XORI, GFMULI, GFMAC, SBOXR = \
    0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F
BLK_SZ = 10
PEEL_SEED = 32
PEEL_LABEL_R = b"CARILLON-PEEL-v2|R|"    # real lane  (what the engine releases)
PEEL_LABEL_D = b"CARILLON-PEEL-v2|D|"    # decoy lane (format-rejectable near-flag)
# The published strict flag validator -- the discriminator that rejects decoys.
STRICT_FLAG = re.compile(rb"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


# ======================================================================
# GF(2^8), AES reduction poly 0x11B (recovered from the engine's gfmul).
# ======================================================================
def _gfmul_slow(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r & 0xFF


GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x = _gfmul_slow(_x, 3)
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def gfmul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gfinv(a):
    if a == 0:
        return 0
    return GF_EXP[255 - GF_LOG[a]]


def mat_inv(A, L):
    M = [row[:] + [1 if i == j else 0 for j in range(L)] for i, row in enumerate(A)]
    for col in range(L):
        piv = None
        for r in range(col, L):
            if M[r][col] != 0:
                piv = r
                break
        if piv is None:
            return None
        M[col], M[piv] = M[piv], M[col]
        inv = gfinv(M[col][col])
        M[col] = [gfmul(x, inv) for x in M[col]]
        for r in range(L):
            if r != col and M[r][col] != 0:
                f = M[r][col]
                M[r] = [M[r][k] ^ gfmul(f, M[col][k]) for k in range(2 * L)]
    return [M[i][L:] for i in range(L)]


def pred(pk, c):
    """Edge selector recovered from the engine; a function of c only."""
    x = c
    pk &= 3
    if pk == 0:   return (x * x - x) & 1
    if pk == 1:   return (x * x + x) & 1
    if pk == 2:   return ((x * x - x) & 1) ^ 1
    return (x * x + x + 1) & 1


def block_ks(bkey, idx):
    return hashlib.sha256(bkey + struct.pack("<I", idx)).digest()[:BLK_SZ]


# ======================================================================
# Nested flag peel (S2/S2a extraction). Recovering the key is NOT the flag:
# the flag is split across NL nested layers, each opened only by the seed the
# previous layer decrypts to. Mirrors peel_layer()/peel_flag() in carillon.c.
# ======================================================================
def _peel_ks(s, tag, n):
    out = b""
    j = 0
    while len(out) < n:
        out += hashlib.sha256(s + tag + struct.pack("<Q", j)).digest()
        j += 1
    return out[:n]


def peel_decrypt(s, ct):
    t = s[0] % 3
    n = len(ct)
    if t == 0:
        ks = _peel_ks(s, b"X", n)
        return bytes(ct[j] ^ ks[j] for j in range(n))
    if t == 1:
        ksa = _peel_ks(s, b"A", n)
        ksb = _peel_ks(s, b"B", n)
        return bytes(gfmul(ct[j] ^ ksb[j], gfinv(ksa[j] | 1)) for j in range(n))
    ksm = _peel_ks(s, b"M", n)
    return bytes((ct[j] - ksm[j]) & 0xFF for j in range(n))


def peel_lane(im, key, lane):
    """Peel one lane ('r' or 'd') of the nested section with `key`.

    Returns (assembled_bytes, tags_ok) where tags_ok[i] is whether layer i's
    stored checksum verifies -- the per-layer gate. No tag is enforced here, so
    this models the engine's output even for a WRONG key (garbage, all-False).
    """
    label = PEEL_LABEL_R if lane == "r" else PEEL_LABEL_D
    s = hashlib.sha256(label + key).digest()
    out, tags_ok = bytearray(), []
    for layer in im["layers"]:
        plen, tag, cti = layer[lane]
        P = peel_decrypt(s, cti)
        frag, nextseed = P[:plen - PEEL_SEED], P[plen - PEEL_SEED:]
        tags_ok.append(hashlib.sha256(s + b"T" + P).digest()[:4] == tag)
        out += frag
        s = nextseed
    return bytes(out), tags_ok


def extract_flag(im, key):
    """Full extraction. Peel the lane whose checksums all pass AND whose
    assembly satisfies the published strict validator -- that reasoning is the
    escape from the decoy lane (guess-exposure 0). Returns (flag, lane)."""
    for lane in ("r", "d"):
        out, tags_ok = peel_lane(im, key, lane)
        if all(tags_ok) and STRICT_FLAG.match(out):
            return out, lane
    # Nothing matched the format (e.g. wrong key): fall back to the real lane.
    return peel_lane(im, key, "r")[0], "r"


# ======================================================================
# Parse + decrypt + lift.
# ======================================================================
def parse_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"CARL":
        raise ValueError("not a CARL image")
    ver, L, R, nreg = data[4], data[5], data[6], data[7]
    flag_len, nblk, entry = struct.unpack_from("<HHH", data, 8)
    bkey = data[16:32]
    off = 32
    sbox = data[off:off + 256]; off += 256
    ct = data[off:off + nblk * BLK_SZ]; off += nblk * BLK_SZ
    expected = data[off:off + L]; off += L
    # --- nested flag-peel section: NL layers, each (decoy lane, real lane) ---
    NL = data[off]; off += 1
    layers = []            # layers[i] = {"d": (plen, tag, ct), "r": (plen, tag, ct)}
    for _ in range(NL):
        lane = {}
        for name in ("d", "r"):
            plen = struct.unpack_from("<H", data, off)[0]; off += 2
            tag = data[off:off + 4]; off += 4
            cti = data[off:off + plen]; off += plen
            lane[name] = (plen, tag, cti)
        layers.append(lane)
    return dict(L=L, R=R, nreg=nreg, flag_len=flag_len, nblk=nblk, entry=entry,
                bkey=bkey, sbox=sbox, ct=ct, expected=expected,
                NL=NL, layers=layers)


def decrypt_block(im, idx):
    ks = block_ks(im["bkey"], idx)
    rec = bytes(c ^ k for c, k in zip(im["ct"][idx * BLK_SZ:idx * BLK_SZ + BLK_SZ], ks))
    op, d, a, imm = rec[0], rec[1], rec[2], rec[3]
    sA = rec[4] | (rec[5] << 8)
    sB = rec[6] | (rec[7] << 8)
    pk, c = rec[8], rec[9]
    return op, d, a, imm, sA, sB, pk, c


def lift_live(im):
    """Decrypt + follow the live edge from entry to HALT. Returns [(op,d,a,imm)]."""
    ops, seen = [], set()
    st = im["entry"]
    while True:
        if st in seen:
            raise ValueError("cycle on live path (unexpected for a valid image)")
        seen.add(st)
        op, d, a, imm, sA, sB, pk, c = decrypt_block(im, st)
        if op == HALT:
            break
        ops.append((op, d, a, imm))
        st = sA if pred(pk, c) else sB
        if st >= im["nblk"]:
            raise ValueError("live edge out of range")
    return ops


# ======================================================================
# Model: segment at S-box layers, recover each affine map symbolically.
# ======================================================================
def recover_affine_layers(ops, L, nreg):
    """Split the op list at full S-box layers (L consecutive SBOXR on regs
    0..L-1) and recover each linear section as (A, c) by symbolic affine
    execution over GF(2^8)."""
    def is_sbox_layer(i):
        if i + L > len(ops):
            return False
        for k in range(L):
            op, d, a, imm = ops[i + k]
            if op != SBOXR or d != k:
                return False
        return True

    sections, cur, i = [], [], 0
    while i < len(ops):
        if is_sbox_layer(i):
            sections.append(cur)
            cur = []
            i += L
        else:
            cur.append(ops[i])
            i += 1
    if cur:
        # a trailing linear section without a closing S-box layer would break
        # the round model; a valid image always ends each round with one.
        raise ValueError("trailing linear ops without an S-box layer")

    layers = []
    for sec in sections:
        # REG[i] carries an affine form (coeffs over the L input vars, const)
        REG = [([0] * L, 0) for _ in range(nreg)]
        for i in range(L):
            co = [0] * L
            co[i] = 1
            REG[i] = (co, 0)
        for (op, d, a, imm) in sec:
            if op == CLR:
                REG[d] = ([0] * L, 0)
            elif op == MOV:
                co, cs = REG[a]
                REG[d] = (co[:], cs)
            elif op == XORI:
                co, cs = REG[d]
                REG[d] = (co, cs ^ imm)
            elif op == GFMULI:
                co, cs = REG[d]
                REG[d] = ([gfmul(x, imm) for x in co], gfmul(cs, imm))
            elif op == GFMAC:
                co, cs = REG[d]
                ao, as_ = REG[a]
                nc = [co[k] ^ gfmul(ao[k], imm) for k in range(L)]
                REG[d] = (nc, cs ^ gfmul(as_, imm))
            elif op == SBOXR:
                raise ValueError("S-box inside a linear section (bad segmentation)")
            else:
                raise ValueError("unknown opcode in lifted program: %#x" % op)
        A = [REG[i][0][:] for i in range(L)]
        c = [REG[i][1] for i in range(L)]
        layers.append((A, c))
    return layers


def matvec(A, v, L):
    out = [0] * L
    for i in range(L):
        acc = 0
        row = A[i]
        for k in range(L):
            if row[k] and v[k]:
                acc ^= gfmul(row[k], v[k])
        out[i] = acc
    return out


def invert(layers, sbox, expected):
    """Peel rounds backwards: undo S-box, then solve A_r in = out(+)c_r."""
    L = len(expected)
    sinv = [0] * 256
    for x, y in enumerate(sbox):
        sinv[y] = x
    x = list(expected)
    for (A, c) in reversed(layers):
        x = [sinv[v] for v in x]                     # undo bytewise S-box
        Ainv = mat_inv(A, L)
        if Ainv is None:
            raise ValueError("affine layer not invertible (model error)")
        xc = [x[i] ^ c[i] for i in range(L)]
        x = matvec(Ainv, xc, L)                      # solve the linear system
    return bytes(x)


def run_forward(ops, sbox, key, L, nreg):
    REG = [0] * nreg
    for i in range(L):
        REG[i] = key[i]
    for (op, d, a, imm) in ops:
        if op == HALT:
            break
        elif op == CLR:    REG[d] = 0
        elif op == MOV:    REG[d] = REG[a]
        elif op == XORI:   REG[d] ^= imm
        elif op == GFMULI: REG[d] = gfmul(REG[d], imm)
        elif op == GFMAC:  REG[d] ^= gfmul(REG[a], imm)
        elif op == SBOXR:  REG[d] = sbox[REG[d]]
    return bytes(REG[:L])


def recover_key(path):
    """End-to-end: image -> recovered key (bytes). Used by the solver + tests."""
    im = parse_image(path)
    ops = lift_live(im)
    layers = recover_affine_layers(ops, im["L"], im["nreg"])
    key = invert(layers, im["sbox"], im["expected"])
    # self-check: forward(key) must reproduce the embedded target
    chk = run_forward(ops, im["sbox"], key, im["L"], im["nreg"])
    if chk != im["expected"]:
        raise ValueError("inversion failed: forward(key) != expected")
    return key, im, ops, layers


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to the .car image")
    ap.add_argument("--bin", help="path to the compiled carillon engine (to win the flag)")
    args = ap.parse_args()

    key, im, ops, layers = recover_key(args.image)

    n_decoy = im["nblk"] - (len(ops) + 1)
    printable = all(32 <= c < 127 for c in key)
    print("[+] lifted %d live instructions (%d blocks in image, ~%d decoys), %d affine layers"
          % (len(ops), im["nblk"], n_decoy, len(layers)))
    print("[+] recovered license key: %s%s"
          % (key.decode("latin-1"), "" if printable else "  (non-printable)"))

    # --- stage 2: the key is only the MEANS to extract -- peel the layers ---
    print("[+] nested flag-peel: %d layers, two lanes each" % im["NL"])
    real_out, real_tags = peel_lane(im, key, "r")
    decoy_out, decoy_tags = peel_lane(im, key, "d")
    print("    real  lane: tags=%s assembles=%r  strict=%s"
          % ("all-pass" if all(real_tags) else "FAIL",
             real_out.decode("latin-1"), bool(STRICT_FLAG.match(real_out))))
    print("    decoy lane: tags=%s assembles=%r  strict=%s  <- rejected by format"
          % ("all-pass" if all(decoy_tags) else "FAIL",
             decoy_out.decode("latin-1"), bool(STRICT_FLAG.match(decoy_out))))
    flag, lane = extract_flag(im, key)
    print("[+] extracted flag (lane %r by the published validator): %s"
          % (lane, flag.decode("latin-1")))

    if not args.bin:
        print("[+] (no --bin given; key + flag recovered by analysis only)")
        return 0

    engine = os.path.abspath(args.bin)
    image = os.path.abspath(args.image)
    proc = subprocess.run([engine, image], input=key + b"\n",
                          capture_output=True, timeout=30)
    out = proc.stdout.decode("latin-1", "replace").strip()
    print("[+] engine response: %s" % out)
    if out.startswith("zerosecurectf{") and out.encode() == flag:
        print("[+] FLAG =", out)
        return 0
    print("[-] did not get a flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
