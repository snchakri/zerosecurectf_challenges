"""
solve.py — C4 NULL STREAM
Organizer reference solution. Implements both solve paths.

PATH A — Binary Analysis (Reverse Engineering)
    Contestant loads encode in radare2 or objdump, identifies:
      - The Galois LFSR loop (shift right, conditional XOR)
      - TAP_MASK constant 0x80200003 as an immediate in the XOR instruction
      - derive_seed: two 4-byte LE loads from the nonce, then XOR
    Then reproduces the keystream in Python and decrypts.

PATH B — Dynamic Cryptanalysis
    Contestant runs the binary on known plaintext to extract a raw keystream,
    applies Berlekamp-Massey to confirm it is a 32-bit LFSR and recover the
    characteristic polynomial (in Fibonacci form).  The tap mask for the Galois
    implementation is then recovered by taking the reciprocal polynomial.
    NOTE: derive_seed (the nonce-to-seed mapping) is NOT recoverable via BM
    alone — it still requires reverse-engineering the binary.  Path B confirms
    the cipher structure and polynomial; Path A supplies the seed derivation.
    Together they form two complementary attack angles, not two fully
    independent solutions.

Run:
    python3 solve.py transmission.null
"""

import sys
import struct

# ── LFSR constants (recovered by contestant via RE) ────────────────────────
TAP_MASK = 0x80200003   # found as immediate in XOR instruction in disassembly
MAGIC    = b'NULLSTRM'  # found via: strings encode
HDR_SIZE = 16


def derive_seed(nonce: bytes) -> int:
    """
    Seed derivation recovered from binary analysis of encode.
    Two 4-byte LE reads from nonce array, then XOR.
    In radare2 this shows as two mov+memcpy sequences followed by xor.
    """
    a = struct.unpack('<I', nonce[0:4])[0]
    b = struct.unpack('<I', nonce[4:8])[0]
    return a ^ b


def lfsr_byte(state: int) -> tuple:
    """
    Galois LFSR step: one byte of keystream (8 clock cycles).
    Each cycle: output bit = state & 1, state >>= 1,
    if output bit == 1: state ^= TAP_MASK.
    Bits packed LSB-first.
    """
    out = 0
    for i in range(8):
        bit   = state & 1
        state = state >> 1
        if bit:
            state ^= TAP_MASK
        out |= (bit << i)
    return (out & 0xFF), state


def decrypt(ciphertext: bytes, nonce: bytes) -> bytes:
    """XOR ciphertext with LFSR keystream (symmetric: encrypt == decrypt)."""
    state = derive_seed(nonce)
    result = bytearray()
    for byte in ciphertext:
        ks, state = lfsr_byte(state)
        result.append(byte ^ ks)
    return bytes(result)


# ── PATH A: solve from known constants ─────────────────────────────────────

def solve_path_a(filepath: str) -> str:
    """
    Direct solve once TAP_MASK and seed derivation are known from RE.
    This is the primary path.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    # Verify magic
    assert data[:8] == MAGIC, f"Bad magic: {data[:8]!r}"

    nonce      = data[8:16]
    ciphertext = data[16:]

    print(f"[+] Magic    : {data[:8].decode()}")
    print(f"[+] Nonce    : {nonce.hex()}")
    print(f"[+] Seed     : {hex(derive_seed(nonce))}")
    print(f"[+] CT size  : {len(ciphertext)} bytes")

    plaintext = decrypt(ciphertext, nonce)

    print("\n[+] Decrypted output:")
    print("=" * 60)
    print(plaintext.decode(errors='replace'))
    print("=" * 60)

    # Extract flag
    for line in plaintext.decode(errors='replace').splitlines():
        if line.startswith('flag{'):
            print(f"\n[+] FLAG: {line.strip()}")
            return line.strip()

    print("[-] Flag not found in plaintext.")
    return ""


# ── PATH B: Berlekamp-Massey cryptanalysis ─────────────────────────────────
#
# Steps (for documentation — not automated here since it requires
# running the encode binary on a Linux machine):
#
# 1. Produce a known keystream by encrypting all-zero input:
#        python3 -c "open('zeros.bin','wb').write(b'\x00'*512)"
#        ./encode zeros.bin ks.enc
#    ks.enc[16:] is raw keystream XOR 0x00 = raw keystream.
#    Nonce for this run: ks.enc[8:16]
#
# 2. Convert keystream bytes to bit stream (LSB first per byte):
#        bits = []
#        for byte in ks_bytes:
#            for i in range(8):
#                bits.append((byte >> i) & 1)
#
# 3. Run Berlekamp-Massey on bits:
#        C, L = berlekamp_massey(bits)
#    Should return L = 32, confirming a 32-bit LFSR.
#    C is the connection polynomial in *Fibonacci* form:
#        C = [1, c1, c2, ..., c32]  (C[0]=1 always, C[32]=1 since L=32)
#
# 4. Convert Fibonacci polynomial to Galois tap mask:
#    BM returns the characteristic polynomial in Fibonacci (external) form.
#    The Galois (internal) form uses the RECIPROCAL polynomial — i.e. the
#    coefficients of C[1:] reversed before building the mask.
#    Use bm_poly_to_galois_mask(C) below; it reverses internally.
#    Result should be 0x80200003, matching the XOR immediate in the binary.
#
#    *** COMMON MISTAKE: applying C directly without reversing gives the
#    Fibonacci tap mask (0xc0000401), NOT the Galois mask. ***
#
# 5. Recover initial state:
#    The first 32 output bits contain enough information to determine the
#    LFSR state at that point.  Run the LFSR backward 32 steps to get the
#    seed, then verify: seed == derive_seed(nonce_from_this_run).
#
# 6. For transmission.null: extract nonce from header bytes 8–15,
#    compute derive_seed(nonce), reproduce keystream, decrypt.
#
#    IMPORTANT: derive_seed (XOR-fold of the two 32-bit nonce halves) is
#    NOT recoverable from the keystream alone — it requires disassembly of
#    encode (Path A).  Path B confirms the cipher structure and the tap mask;
#    Path A is still needed for the nonce-to-seed function.


def berlekamp_massey(bits: list) -> tuple:
    """
    Berlekamp-Massey algorithm over GF(2).
    Returns (C, L) where C is the connection polynomial [1, c1, ..., cL]
    in Fibonacci form, and L is the LFSR length (degree of C).
    Input needs at least 2*L bits for correct recovery (use >= 128 bits).
    """
    n = len(bits)
    C = [1]
    B = [1]
    L = 0
    x = 1

    for i in range(n):
        # Compute discrepancy
        d = bits[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] * bits[i - j]

        if d == 0:
            x += 1
            continue

        T = C[:]
        # Extend C if needed, then update
        while len(C) < len(B) + x:
            C.append(0)
        for j in range(len(B)):
            C[j + x] = (C[j + x] + B[j]) % 2

        if 2 * L <= i:
            L = i + 1 - L
            B = T
            x = 1
        else:
            x += 1

    return C[:L + 1], L


def bm_poly_to_galois_mask(C: list) -> int:
    """
    Convert a BM connection polynomial (Fibonacci form) to a Galois LFSR
    tap mask.

    BM returns the characteristic polynomial coefficients in Fibonacci
    (external feedback) form:
        C = [1, c1, c2, ..., cL]   where C[0]=1 and C[L]=1

    A Galois (internal feedback) LFSR implements the same polynomial but
    uses the RECIPROCAL polynomial, whose coefficients are C[1:] reversed.
    The tap mask is then built from the reversed coefficients.
    """
    L = len(C) - 1
    # Reverse the non-leading coefficients to get the reciprocal polynomial
    C_rev = [C[0]] + list(reversed(C[1:]))
    mask = 0
    for i in range(1, len(C_rev)):
        if C_rev[i]:
            mask |= (1 << (L - i))
    return mask


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"usage: python3 {sys.argv[0]} <transmission.null>")
        sys.exit(1)

    flag = solve_path_a(sys.argv[1])
    if not flag:
        sys.exit(1)
