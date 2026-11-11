"""
generate_transmission.py
Generates transmission.null for C4_NULL_STREAM.

This script implements the exact same Galois LFSR as encode.c.
Run this to (re)produce contestant_package/transmission.null.

Usage:
    python3 generate_transmission.py

Output:
    ../contestant_package/transmission.null

Verification:
    The script prints the nonce and seed so organizers can confirm
    the solve.py decrypts correctly.
"""

import struct
import os

# ── LFSR parameters (must match encode.c exactly) ──────────────────────────
TAP_MASK = 0x80200003
MAGIC    = b'NULLSTRM'

# Fixed nonce for reproducible challenge.
# This nonce is embedded in transmission.null bytes 8–15.
# Contestants extract it with: xxd transmission.null | head -1
NONCE = bytes([0xa3, 0xf7, 0xc2, 0xd8, 0x41, 0xb9, 0xe6, 0x05])


def derive_seed(nonce: bytes) -> int:
    """
    XOR-fold of two 4-byte little-endian halves of the nonce.
    Matches the C implementation:
        uint32_t a, b;
        memcpy(&a, nonce, 4);
        memcpy(&b, nonce+4, 4);
        return a ^ b;
    """
    a = struct.unpack('<I', nonce[0:4])[0]
    b = struct.unpack('<I', nonce[4:8])[0]
    return a ^ b


def lfsr_byte(state: int) -> tuple:
    """
    Galois LFSR: produce one output byte (8 clock cycles).
    Returns (byte, new_state).
    Bit 0 of the result is the first clock's output bit.
    Matches the C lfsr_byte() function exactly.
    """
    out = 0
    for i in range(8):
        bit   = state & 1
        state = state >> 1
        if bit:
            state ^= TAP_MASK
        out |= (bit << i)
    return (out & 0xFF), state


def encrypt(plaintext: bytes, nonce: bytes) -> bytes:
    """Encrypt plaintext with Galois LFSR using nonce-derived seed."""
    state = derive_seed(nonce)
    result = bytearray()
    for byte in plaintext:
        ks, state = lfsr_byte(state)
        result.append(byte ^ ks)
    return bytes(result)


# ── Plaintext content of transmission.null ─────────────────────────────────
# The flag is embedded naturally in the message.
# Players who successfully decrypt see this full text.
PLAINTEXT = (
    b"STATIC BROTHERHOOD -- ENCRYPTED CHANNEL LOG\n"
    b"SESSION: SB-NOV-2024-047\n"
    b"OPERATOR: WRAITH\n"
    b"\n"
    b"Transfer confirmed. The secondary archive is live.\n"
    b"Credentials rotated. NEXUS contact acknowledged receipt.\n"
    b"\n"
    b"Do not use the primary channel after this transmission.\n"
    b"Burn the endpoint. Leave nothing cached.\n"
    b"\n"
    b"flag{static_is_just_a_keystream_waiting_to_be_read}\n"
    b"\n"
    b"-- channel closed --\n"
)


def main():
    seed = derive_seed(NONCE)
    ciphertext = encrypt(PLAINTEXT, NONCE)
    output = MAGIC + NONCE + ciphertext

    out_path = os.path.join(
        os.path.dirname(__file__),
        '..', '..', 'contestant_package', 'transmission.null'
    )
    out_path = os.path.normpath(out_path)

    with open(out_path, 'wb') as f:
        f.write(output)

    print(f"[+] Generated: {out_path}")
    print(f"[+] Total size : {len(output)} bytes")
    print(f"[+] Header     : {MAGIC.decode()} + nonce")
    print(f"[+] Nonce (hex): {NONCE.hex()}")
    print(f"[+] Seed       : {hex(seed)}")
    print(f"[+] Plaintext  : {len(PLAINTEXT)} bytes")
    print()
    print("[+] Verification — decrypting with same key:")
    decrypted = encrypt(ciphertext, NONCE)  # XOR is its own inverse
    assert decrypted == PLAINTEXT, "DECRYPTION MISMATCH — check implementation"

    flag_line = next(
        l for l in decrypted.decode().splitlines() if l.startswith('flag{')
    )
    print(f"    Flag line: {flag_line}")
    print("[+] Verification passed.")


if __name__ == '__main__':
    main()
