"""
Cipher specification for crypto_12_feal4_cryptanalysis  (player handout).

This is a reduced-width FEAL-4: a 4-round Feistel network on a 32-bit block
(two 16-bit halves), with four independent 16-bit round keys K0..K3. The round
function F is built from FEAL's signature operations — byte addition mod 256
followed by a left-rotation by 2 — which is exactly what makes the cipher
vulnerable to differential cryptanalysis.

The four round keys are SECRET and are NOT contained in this file. Everything
else about the cipher is public and given here.

How the flag was encrypted (CTR mode, see plaintext_pairs.json):
    keystream_block_i = encrypt_block((nonce + i) mod 2^32, K)
    flag[4i:4i+4]    ^= keystream_block_i  (big-endian 4 bytes per block)
"""


def ROL2(x):
    return ((x << 2) | (x >> 6)) & 0xFF


def S0(a, b):
    return ROL2((a + b) & 0xFF)


def S1(a, b):
    return ROL2((a + b + 1) & 0xFF)


def F16(x):
    """Round function: 16 bits -> 16 bits."""
    x0 = (x >> 8) & 0xFF
    x1 = x & 0xFF
    y0 = S0(x0, x1)
    y1 = S1(x1, y0)
    return (y0 << 8) | y1


def encrypt_block(pt, K):
    """4-round Feistel. pt is a 32-bit int; K = [K0, K1, K2, K3] (16-bit each)."""
    L = (pt >> 16) & 0xFFFF
    R = pt & 0xFFFF
    for i in range(4):
        L, R = R, L ^ F16(R ^ K[i])
    return (L << 16) | R


def decrypt_block(ct, K):
    L = (ct >> 16) & 0xFFFF
    R = ct & 0xFFFF
    for i in range(3, -1, -1):
        # invert: previous (L_prev, R_prev) with L=R_prev, R=L_prev ^ F16(R_prev^K)
        L, R = R ^ F16(L ^ K[i]), L
    return (L << 16) | R
