"""
solve.py — C5 ENTROPY GRAVE  (v2 — fixed)
Organizer reference solution. Implements the full intended solve path.

Intended path:
  1. file evidence.img          -> raw data (not a filesystem)
  2. strings evidence.img       -> finds log fragment with two key clues:
                                   (a) "prime difference unusually small"
                                       -> research -> Fermat's factorization
                                   (b) "config.db relocated ... [sector 0x800]"
                                       -> points to SQLite location
  3. binwalk evidence.img       -> finds SQLite at offset 0x800
     binwalk -e evidence.img    -> extracts config.db
     (Python fallback shown below — works without binwalk)
  4. sqlite3 config.db          -> query n (modulus), e, ciphertext payload
  5. Python:
       - Fermat's factorization on n -> p, q
       - reconstruct d = e^-1 mod phi(n)
       - textbook RSA decrypt: m = c^d mod n
       - decode plaintext -> flag

Contestant paths (all valid — this script covers Path B, Python-only):
  Path A: file -> strings -> binwalk -e -> sqlite3 CLI -> custom script
  Path B: file -> strings -> Python magic-byte extract -> Python sqlite3
  Path C: hexdump -> dd skip=2048 -> sqlite3 CLI -> custom script
  Path D: forensic suite (autopsy/foremost) -> sqlite3 -> custom script
  Path E: all-in-one Python script (what this file does)

Run:
    python3 solve.py evidence.img
"""

import sys
import os
import sqlite3
import tempfile
from math import isqrt


# ── Step 1: Extract SQLite from disk image ──────────────────────────────────

def extract_sqlite(image_path: str) -> bytes:
    """
    Locate the SQLite magic bytes in the disk image and extract the database.
    This is what a contestant does with: binwalk -e evidence.img
    The WSL/Python fallback:
        data = open('evidence.img','rb').read()
        magic = b'SQLite format 3\x00'
        off = data.find(magic)
        open('config.db','wb').write(data[off:])
    """
    with open(image_path, 'rb') as f:
        data = f.read()

    magic = b'SQLite format 3\x00'
    offset = data.find(magic)
    if offset == -1:
        raise ValueError("SQLite magic not found in image")

    print(f"[+] SQLite found at offset: {hex(offset)}")
    db_bytes = data[offset:]
    return db_bytes


def load_sqlite(db_bytes: bytes) -> tuple:
    """
    Write db_bytes to a temp file, query it with sqlite3, return (n, e, c).

    n and c are stored as BLOBs (raw big-endian bytes).
    Python's sqlite3 module returns BLOB columns as bytes objects directly.
    All queries use column NAMES — column order in the schema is irrelevant.

    A contestant using the sqlite3 CLI would do:
        SELECT label, e, key_size, notes FROM key_config;
        SELECT hex(modulus) FROM key_config;       -- get n as hex string
        SELECT algorithm, length(payload) FROM encrypted_records;
        SELECT hex(payload) FROM encrypted_records; -- get c as hex string
    Then convert: n = int(hex_str, 16), c = int(hex_str, 16)

    Or use Python sqlite3 which returns BLOBs as bytes objects directly
    (no hex conversion needed — just int.from_bytes(blob, 'big')).
    """
    tmp = tempfile.mktemp(suffix='.db')
    try:
        with open(tmp, 'wb') as f:
            f.write(db_bytes)

        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()

        # modulus is a BLOB — Python sqlite3 returns it as bytes
        cur.execute("SELECT modulus, e FROM key_config WHERE id = 1")
        row = cur.fetchone()
        n_bytes, e = row
        n = int.from_bytes(n_bytes, 'big')

        # payload is a BLOB — returned as bytes
        cur.execute("SELECT payload FROM encrypted_records WHERE id = 1")
        row = cur.fetchone()
        c_bytes = row[0]
        c = int.from_bytes(c_bytes, 'big')

        conn.close()

        print(f"[+] n = {n.bit_length()}-bit modulus")
        print(f"[+] e = {e}")
        print(f"[+] c = {c.bit_length()}-bit ciphertext")

        return n, e, c

    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ── Step 2: Fermat's Factorization ──────────────────────────────────────────

def fermat_factor(n: int) -> tuple:
    """
    Fermat's factorization algorithm.

    Works when n = p*q and |p-q| is small relative to sqrt(n).
    Start at a = ceil(sqrt(n)), increment until a^2 - n is a perfect square.
    Then p = a - b, q = a + b where b = sqrt(a^2 - n).

    With |p-q| < 2^16 and 512-bit primes, this terminates in at most a
    few hundred steps (upper bound ~1000). For the default challenge key
    pair, it terminates in exactly 0 iterations: isqrt(n)+1 is already
    the correct value of 'a', so the very first candidate is the solution.
    A result of "Factored in 0 iterations" is correct and expected.

    Exploits the fact that a badly seeded PRNG generated p and q in the
    same entropy window — they started from nearly the same seed.

    The log clue: "prime difference unusually small"
    """
    print("[*] Running Fermat's factorization ...")
    a = isqrt(n) + 1
    steps = 0
    while True:
        b2 = a * a - n
        b  = isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            print(f"[+] Factored in {steps} iterations")
            print(f"[+] p = {p.bit_length()}-bit prime")
            print(f"[+] q = {q.bit_length()}-bit prime")
            print(f"[+] |p - q| = {abs(p - q)}")
            return p, q
        a += 1
        steps += 1
        if steps > 10_000_000:
            raise ValueError("Fermat did not converge — primes may not be close")


# ── Step 3: RSA Decrypt ─────────────────────────────────────────────────────

def rsa_decrypt(c: int, e: int, p: int, q: int) -> bytes:
    """
    Textbook RSA decryption.
    d = e^-1 mod phi(n)
    m = c^d mod n
    Labeled RSA-1024-RAW in the database: no padding.
    """
    phi = (p - 1) * (q - 1)
    d   = pow(e, -1, phi)
    m   = pow(c, d, p * q)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big')


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"usage: python3 {sys.argv[0]} <evidence.img>")
        sys.exit(1)

    image_path = sys.argv[1]
    print(f"[+] Image: {image_path}")

    db_bytes = extract_sqlite(image_path)
    n, e, c  = load_sqlite(db_bytes)
    p, q     = fermat_factor(n)

    # Verify primes are correct
    assert p * q == n, "p*q != n — factorization wrong"

    plaintext = rsa_decrypt(c, e, p, q)

    print("\n[+] Decrypted report:")
    print("=" * 60)
    print(plaintext.decode(errors='replace'))
    print("=" * 60)

    for line in plaintext.decode(errors='replace').splitlines():
        if line.startswith('flag{'):
            print(f"\n[+] FLAG: {line.strip()}")
            return

    print("[-] Flag line not found.")


if __name__ == '__main__':
    main()
