#!/usr/bin/env python3
"""
ZeroSecure CTF 2024 — Broadcast: SOLVER
========================================
Håstad's Broadcast Attack against RSA with e=3 and no padding.

Requires: sympy  (pip install sympy)
"""

from sympy.ntheory.modular import crt
from sympy import integer_nthroot

# ── Challenge parameters ──────────────────────────────────────────────────────

e = 3

n1 = 0xC0CDF59462A6DB5CDBA0A030CCA2A3E49A1F6558B1BE4398D96F3C74C40A47B9DA68CF73B4F73F8D26EA5DC6A218DB78EDDB84E7A8DE0A8B5A0BD70B5B5B3D23
n2 = 0xBA0A0F4EA97B2A7E66B2A0C2D8D4F12AFBCF04E7783943B3E4C6A3DE92A3E4B5F90DBAEFCA43B29A3CF4E7B1DAB39CF4E4C3D2B1A08F7E6D5C4B3A291817160
n3 = 0xD2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D3

c1 = 0x1D4A7F2E9B6C3850F1A2D4E7B9C0F3A6D8E1B4C7F2A5D8E0B3C6F9A2D5E8B1C4F7A0D3E6B9C2F5A8D1E4B7C0F3A6D9E2B5C8F1A4D7E0B3C6F9A2D5E8B1C4
c2 = 0x2B5E8F1C4A7D0E3B6C9F2A5D8E1B4C7F0A3D6E9B2C5F8A1D4E7B0C3F6A9D2E5B8C1F4A7D0E3B6C9F2A5D8E1B4C7F0A3D6E9B2C5F8A1D4E7B0C3F6A9D2E5
c3 = 0x3C6F9A2D5E8B1C4F7A0D3E6B9C2F5A8D1E4B7C0F3A6D9E2B5C8F1A4D7E0B3C6F9A2D5E8B1C4F7A0D3E6B9C2F5A8D1E4B7C0F3A6D9E2B5C8F1A4D7E0B3C7

# ── Attack ────────────────────────────────────────────────────────────────────

def hastad_broadcast_attack(ns, cs, e):
    """
    Håstad's Broadcast Attack.

    Given e ciphertexts encrypted under the same e and different moduli,
    uses CRT to recover m^e over the integers, then takes the e-th root.

    Args:
        ns : list of moduli [n1, n2, ..., ne]
        cs : list of ciphertexts [c1, c2, ..., ce]
        e  : public exponent (must equal len(ns))

    Returns:
        plaintext integer m, or None if cube root is not exact.
    """
    assert len(ns) == e == len(cs), "Need exactly e (modulus, ciphertext) pairs"

    # Step 1: CRT — recover m^e mod (n1 * n2 * ... * ne)
    # Because m^e < product of all ni, this IS m^e over the integers.
    _, m_e = crt(ns, cs)

    # Step 2: Integer e-th root (no modular reduction)
    m_int, is_exact = integer_nthroot(m_e, e)

    if not is_exact:
        return None
    return m_int


def long_to_bytes(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Running Håstad's Broadcast Attack (e=3, 3 recipients)...")

    m = hastad_broadcast_attack([n1, n2, n3], [c1, c2, c3], e)

    if m is None:
        print("[!] Cube root was not exact — check your parameters.")
    else:
        flag = long_to_bytes(m).decode()
        print(f"[+] Recovered plaintext : {flag}")
        assert flag.startswith("ZeroSecure_ctf{"), "Unexpected flag format"
        print(f"[+] Flag                : {flag}")

# ── Why this works ────────────────────────────────────────────────────────────
#
#  RSA encryption: c ≡ m^e (mod n)
#
#  With e=3 and three recipients using different moduli n1, n2, n3:
#
#    c1 ≡ m³ (mod n1)
#    c2 ≡ m³ (mod n2)
#    c3 ≡ m³ (mod n3)
#
#  By CRT (n1,n2,n3 pairwise coprime), there is a UNIQUE solution x
#  satisfying all three congruences mod N = n1*n2*n3.
#
#  That solution is x = m³ in the integers (not reduced), because
#  m³ < N when m fits in ~256 bits and each n is ~512 bits.
#
#  Therefore: m = ∛x  (integer cube root, exact)
#
#  Fix: use randomized padding (OAEP / PKCS#1 v2.1) so each
#  encryption of the same message produces a different ciphertext.
