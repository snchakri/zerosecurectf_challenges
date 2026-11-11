# solve.py -- ORGANIZER ONLY -- DO NOT DISTRIBUTE
#
# WARD 7 -- Full solution
# Vulnerability: RSA Common Modulus Attack
#
# MATHEMATICAL BASIS:
#   c1 = m^e1 mod n   (same doc encrypted for admin Blaha, e1=65537)
#   c2 = m^e2 mod n   (same doc encrypted for admin Cerna, e2=65539)
#
#   gcd(65537, 65539) = 1  (coprime -- attack is valid)
#   Extended Euclidean: find a,b where a*65537 + b*65539 = 1
#     a = 32769, b = -32768
#   (verify: 32769*65537 - 32768*65539 = 65537 - 65536 = 1)
#
#   m = c1^a * c2^b mod n
#   Since b < 0: c2^b mod n = modinv(c2,n)^|b| mod n
#
# SECOND LAYER: Digit-sequence poly-shift cipher
#   Key digits extracted from case reference CASE-1943-29: [1,9,4,3,2,9]
#   Each alpha character in the encoded flag is shifted by the next key digit (cycling)
#   This is a poly-alphabetic substitution -- NOT brute-forceable via Caesar
#   Players must read the document, extract the case number, and apply the digit sequence
#
# UNINTENDED SOLVE PATHS:
#   - Factoring n: n is 8192-bit, completely infeasible
#   - Caesar brute force: BLOCKED -- new encoding does not yield FLAG{ under any single shift
#   - Vigenere brute force: key space is 10^6 digit sequences (impractical without the narrative)
#
# No external libraries required. Pure Python math only.

import re
import os

def xgcd(a, b):
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where a*x + b*y = gcd."""
    old_r, r = a, b
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    old_t = (old_r - old_s * a) // b if b else 0
    return old_r, old_s, old_t

def modinv(a, m):
    """Modular multiplicative inverse of a mod m."""
    g, x, _ = xgcd(a % m, m)
    assert g == 1, "gcd != 1, inverse does not exist"
    return x % m

def digit_seq_decode(text, digits):
    """
    Poly-shift decode: each alpha character is shifted back by the next digit
    in `digits` (cycling). Non-alpha characters are passed through unchanged.
    Key digits come from the case reference number in the recovered document.
    """
    out = []
    di = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base - digits[di % len(digits)]) % 26 + base))
            di += 1
        else:
            out.append(c)
    return ''.join(out)

print("=" * 60)
print("WARD 7 -- Solution")
print("=" * 60)

# Step 1: Parse keystore.txt (path relative to this script's location)
print("\n[Step 1] Parse keystore.txt")
keystore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             '..', 'contestant_package', 'keystore.txt')
# Fallback: try current directory (for running directly from contestant_package/)
if not os.path.exists(keystore_path):
    keystore_path = 'keystore.txt'

raw   = open(keystore_path).read()
all_n = [int(x) for x in re.findall(r'pubkey_n\s*=\s*(\d+)', raw)]
all_e = [int(x) for x in re.findall(r'pubkey_e\s*=\s*(\d+)', raw)]
all_c = [int(x) for x in re.findall(r'ciphertext\s*=\s*(\d+)', raw)]

n  = all_n[0]
e1 = all_e[0]   # 65537 (Blaha)
e2 = all_e[1]   # 65539 (Cerna)
c1 = all_c[0]
c2 = all_c[1]

print(f"  n  (Blaha): {str(n)[:40]}...")
print(f"  n  (Cerna): {str(all_n[1])[:40]}...")
print(f"  Moduli identical: {all_n[0] == all_n[1]}")
assert all_n[0] == all_n[1], "FAIL: moduli differ -- challenge data corrupted"
print(f"  e1 = {e1}  (Blaha)")
print(f"  e2 = {e2}  (Cerna)")

# Step 2: Common modulus attack
print("\n[Step 2] RSA Common Modulus Attack")
g, a, b = xgcd(e1, e2)
assert g == 1, f"gcd(e1,e2) = {g}, must be 1"
print(f"  gcd({e1}, {e2}) = {g}  (coprime, attack valid)")
print(f"  Bezout coefficients: a={a}, b={b}")
print(f"  Verify: {a}*{e1} + ({b})*{e2} = {a*e1 + b*e2}  (should be 1)")
assert a * e1 + b * e2 == 1

base1 = modinv(c1, n) if a < 0 else c1
exp1  = abs(a)
base2 = modinv(c2, n) if b < 0 else c2
exp2  = abs(b)

print(f"\n  Computing: m = c1^{a} * c2^{b} mod n")
if b < 0:
    print(f"  c2^{b} -> modinv(c2,n)^{exp2}")

m_int   = (pow(base1, exp1, n) * pow(base2, exp2, n)) % n
m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')

print("\n[Step 3] Recovered document")
print("-" * 50)
document = m_bytes.decode('utf-8')
print(document)
print("-" * 50)

# Step 4: Extract case number digits and decode flag
print("\n[Step 4] Decode the flag")
case_match = re.search(r'(CASE-[\d-]+)', document)
case_ref   = case_match.group(1)
key_digits = [int(c) for c in case_ref if c.isdigit()]
print(f"  Case reference: {case_ref}")
print(f"  Key digit sequence: {key_digits}")
print(f"  Cipher: poly-shift -- each alpha char shifted by successive key digit (cycling)")

encoded_line = re.search(r'INTEGRITY CHECK\n(.+)', document)
encoded      = encoded_line.group(1).strip()
print(f"  Encoded:  {encoded}")
flag         = digit_seq_decode(encoded, key_digits)
print(f"\n[+] FLAG: {flag}")
