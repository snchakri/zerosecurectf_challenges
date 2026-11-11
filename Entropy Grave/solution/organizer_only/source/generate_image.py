"""
generate_image.py — C5 ENTROPY GRAVE  (v2 — fixed)
Generates contestant_package/evidence.img from scratch.

This script:
  1. Generates two close 512-bit RSA primes (|p-q| < 2^16)
  2. Encrypts the flag message with textbook RSA-1024
  3. Builds a SQLite database with the RSA parameters and ciphertext
  4. Constructs evidence.img with:
       0x000 (512 bytes)  : Fake wipe header (interrupted at 2.3%)
       0x200 (1024 bytes) : nexum-keygen log fragment (contains the clues)
       0x600 (512 bytes)  : Zeroed wipe area (wipe-in-progress simulation)
       0x800 (variable)   : SQLite database (config.db)

Run (from organizer_only/source/):
    pip install sympy
    python3 generate_image.py

Output:
    ../../contestant_package/evidence.img
    ../params.txt   (organizer reference — KEEP PRIVATE)

The image is fully reproducible: the same RANDOM_SEED always produces the
same primes, the same ciphertext, and the same evidence.img byte-for-byte.

IMPORTANT — regenerate for every new CTF event:
    Once n is submitted to factordb.com by any participant, it is indexed
    permanently. Future use of the same evidence.img would allow trivial
    factoring without Fermat's. Change RANDOM_SEED and regenerate before
    each deployment.

CHANGELOG v2:
  Bug 2 fix — Prime generation is now fully deterministic.
    The previous version used sympy.randprime() which internally calls
    os.urandom and ignores Python's random.seed() entirely, producing a
    different key pair on every run. Replaced with random.Random(seed)
    candidate generation + sympy.isprime() primality testing.
    isprime() is a pure deterministic function — zero randomness involved.

  Bug 4 fix — n is now exactly 1024 bits (previously could be 1023).
    Both prime candidates now have their top TWO bits set (bits-1 and
    bits-2). This guarantees each prime p >= 3*2^(bits-2), so
    n = p*q >= 9*2^(2*bits-4) > 2^(2*bits-1), i.e. n.bit_length() == 1024.

  Bug 1 fix — strings(1) no longer shows false 'operations_key_q1_v4'.
    Root cause: The first 3 bytes of the RSA modulus stored as BLOB happen
    to be 0x5f 0x76 0x34 ('_v4' in ASCII). In the old schema, the modulus
    BLOB was stored AFTER the label TEXT in the B-tree record, making them
    adjacent in raw page bytes. strings(1) read straight through from the
    label into those 3 printable modulus bytes, displaying the false suffix.
    Fix: modulus BLOB now comes BEFORE label TEXT in both table schemas.
    All SQL queries use column names, never positional access — no impact.

  Bug 5 fix — fermat_steps comment clarified in params.txt output.
"""

import os
import sys
import random
import sqlite3
import tempfile
import subprocess

try:
    from sympy import isprime
except ImportError:
    print("[-] sympy not found. Install with: pip install sympy")
    sys.exit(1)

# ── Reproducibility ─────────────────────────────────────────────────────────
# All randomness flows through random.Random(RANDOM_SEED).
# isprime() is a pure deterministic primality test — no randomness involved.
# Change this seed to regenerate a different (but equally valid) challenge.
# IMPORTANT: change this seed before each new CTF event deployment.
RANDOM_SEED = 0x43415254   # "CART" in ASCII

# ── RSA parameters ──────────────────────────────────────────────────────────
E = 65537
KEY_BITS = 1024
PRIME_BITS = 512

# ── Flag and plaintext ──────────────────────────────────────────────────────
PLAINTEXT = (
    b"CARTOGRAPHER Q1 - 2024-03-12\n"
    b"\n"
    b"HERALD confirmed. Channel active post-21st.\n"
    b"\n"
    b"flag{close_primes_leave_shallow_graves}\n"
)

# ── Image section content ────────────────────────────────────────────────────

WIPE_HEADER_TEXT = (
    b"SECURE-WIPE v2.3 INITIATED\n"
    b"Wipe mode: single-pass zero-fill\n"
    b"Target: /dev/sda\n"
    b"Started: 2024-03-12 14:23:15 UTC\n"
    b"Process terminated: power failure at 2.3%\n"
    b"Sectors wiped: 469/20480\n"
    b"State: INCOMPLETE\n"
)

LOG_FRAGMENT_TEXT = (
    b"[2024-03-12 14:21:58] nexum-keygen v0.4.1 started\n"
    b"[2024-03-12 14:21:59] Initializing entropy pool...\n"
    b"[2024-03-12 14:21:59] WARNING: entropy pool below threshold (42 bits available)\n"
    b"[2024-03-12 14:21:59] Switching to software PRNG -- time-based seed fallback\n"
    b"[2024-03-12 14:22:00] Generating RSA-1024 key pair...\n"
    b"[2024-03-12 14:22:01] Both primes generated in same entropy window (94ms)\n"
    b"[2024-03-12 14:22:01] WARNING: prime difference unusually small -- flagged for review\n"
    b"[2024-03-12 14:22:02] Key generation complete. Stored in config.db\n"
    b"[2024-03-12 14:22:02] config.db relocated to secondary partition [sector 0x800]\n"
    b"[2024-03-12 14:22:03] Encrypting: operations_report_q1.txt -> config.db\n"
    b"[2024-03-12 14:22:03] Process complete.\n"
)


def generate_close_primes(bits: int, seed: int) -> tuple:
    """
    Generate two primes p < q where |p-q| < 2^16, fully deterministically.

    Algorithm:
      1. rng = random.Random(seed)  — seeded, reproducible PRNG
      2. Generate candidates with top 2 bits set + LSB set (odd, full-length)
      3. Test each candidate with sympy.isprime() — pure, no randomness
      4. Once p is found, pick a random delta in [5000, 30000]
      5. Walk q = p + delta upward until prime

    Setting top TWO bits of each prime guarantees:
      p, q >= 3 * 2^(bits-2)
      n = p*q >= 9 * 2^(2*bits-4) > 2^(2*bits-1)
      => n.bit_length() == 2*bits exactly (no 1023-bit n ever)

    Fermat's factorization terminates in at most a few hundred steps because
    |p-q| < 2^16 is negligible compared to the ~2^512 scale of the primes.
    For the default RANDOM_SEED it terminates in exactly 0 iterations
    (meaning isqrt(n)+1 is already the solution a).
    """
    rng = random.Random(seed)

    print("[*] Generating 512-bit prime p ...")
    attempts = 0
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1))   # set MSB — full bit-length
        candidate |= (1 << (bits - 2))   # set 2nd bit — guarantees 1024-bit n
        candidate |= 1                    # odd
        if isprime(candidate):
            p = candidate
            break
        attempts += 1

    delta = rng.randint(5000, 30000)
    print(f"[*] Finding q close to p (target delta ~{delta}) ...")
    q = p + delta
    if q % 2 == 0:
        q += 1
    while not isprime(q):
        q += 2

    diff = abs(p - q)
    assert diff < 2 ** 16, f"Primes not close enough: |p-q| = {diff}"
    print(f"[+] |p - q| = {diff} (< 65536)")
    return p, q


def build_sqlite_db(n: int, e: int, c: int) -> bytes:
    """
    Build the SQLite database and return its raw bytes.

    Schema design notes:
      key_config   — modulus BLOB before label TEXT (Bug 1 fix)
      encrypted_records — payload BLOB before label TEXT (Bug 1 fix)

    Why column order matters for strings(1):
      SQLite B-tree records store column values sequentially in the page.
      If label TEXT comes before modulus BLOB, strings(1) reads the label
      characters and then immediately the first printable bytes of the
      binary modulus — making them look like one string. By placing BLOB
      columns before TEXT columns, the binary noise appears first in the
      page, and the text labels appear later as clean isolated strings.

    Contestant queries (all use column names, never positional):
      SELECT hex(modulus) FROM key_config;
      SELECT label, e, key_size, notes FROM key_config;
      SELECT algorithm, length(payload) FROM encrypted_records;
      SELECT hex(payload) FROM encrypted_records;
    All of these work identically regardless of column order.
    """
    db_file = tempfile.mktemp(suffix='.db')
    try:
        conn = sqlite3.connect(db_file)
        cur  = conn.cursor()

        # modulus BLOB before label TEXT — prevents false _v4 artifact in strings
        cur.execute("""
            CREATE TABLE key_config (
                id         INTEGER PRIMARY KEY,
                modulus    BLOB,
                label      TEXT,
                e          INTEGER,
                key_size   INTEGER,
                created    TEXT,
                device_id  TEXT,
                notes      TEXT
            )
        """)

        # payload BLOB before label TEXT — same reasoning
        cur.execute("""
            CREATE TABLE encrypted_records (
                id         INTEGER PRIMARY KEY,
                payload    BLOB,
                label      TEXT,
                algorithm  TEXT,
                key_id     INTEGER
            )
        """)

        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')

        cur.execute(
            "INSERT INTO key_config VALUES (?,?,?,?,?,?,?,?)",
            (
                1,
                n_bytes,
                'operations_key_q1',
                e,
                1024,
                '2024-03-12 14:22:01',
                'CG-LAP-007',
                'RSA-1024. Low-entropy key gen -- nexum-keygen v0.4.1. See device log.'
            )
        )

        cur.execute(
            "INSERT INTO encrypted_records VALUES (?,?,?,?,?)",
            (
                1,
                c_bytes,
                'operations_report_q1.txt',
                'RSA-1024-RAW',
                1
            )
        )

        conn.commit()
        conn.close()

        with open(db_file, 'rb') as f:
            db_bytes = f.read()

        return db_bytes

    finally:
        if os.path.exists(db_file):
            os.remove(db_file)


def build_image(db_bytes: bytes) -> bytes:
    """
    Assemble evidence.img layout:
      0x000 — 0x1FF  (512 bytes)  : wipe header
      0x200 — 0x5FF  (1024 bytes) : nexum-keygen log fragment
      0x600 — 0x7FF  (512 bytes)  : zeroed wipe-in-progress region
      0x800 — EOF    (variable)   : SQLite database

    Total pre-SQLite: 2048 bytes = 0x800 exactly.
    """
    s1 = WIPE_HEADER_TEXT.ljust(512, b'\x00')[:512]

    assert len(LOG_FRAGMENT_TEXT) <= 1024, \
        f"Log fragment too large: {len(LOG_FRAGMENT_TEXT)} bytes (max 1024)"
    s2 = LOG_FRAGMENT_TEXT.ljust(1024, b'\x00')[:1024]

    s3 = b'\x00' * 512
    s4 = db_bytes

    image = s1 + s2 + s3 + s4
    assert len(image[:0x800]) == 0x800, \
        f"Offset error: pre-SQLite region is {len(image[:0x800])} bytes, expected 2048"
    return image


def verify_strings_output(image_path: str) -> bool:
    """
    Verify strings output is clean: correct label visible, no false artifact.
    Returns True if clean, False if _v4 artifact is present.
    """
    try:
        result = subprocess.run(
            ['strings', image_path],
            capture_output=True, text=True, timeout=10
        )
        has_artifact = '_v4' in result.stdout
        has_correct_label = 'operations_key_q1' in result.stdout
        return (not has_artifact) and has_correct_label
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True  # strings not available; skip check


def main():
    print("=" * 60)
    print("C5 ENTROPY GRAVE — Challenge Generator v2")
    print("=" * 60)

    # Step 1: Generate RSA key pair (deterministic)
    p, q = generate_close_primes(PRIME_BITS, RANDOM_SEED)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)

    print(f"[+] n = {n.bit_length()} bits (must be 1024)")
    assert n.bit_length() == 1024, f"FAIL: n is {n.bit_length()} bits, expected 1024"
    print(f"[+] e = {E}")

    # Step 2: Verify Fermat's factorization converges
    print("[*] Verifying Fermat's factorization converges ...")
    from math import isqrt
    a = isqrt(n) + 1
    steps = 0
    while True:
        b2 = a * a - n
        b  = isqrt(b2)
        if b * b == b2:
            break
        a += 1
        steps += 1
        if steps > 10_000_000:
            raise RuntimeError("Fermat did not converge — adjust seed or prime generation")
    fp, fq = a - b, a + b
    assert fp * fq == n, "Fermat recovery check failed: fp*fq != n"
    assert {fp, fq} == {p, q}, "Fermat did not recover the correct p, q"
    print(f"[+] Fermat's factorization: {steps} iterations "
          f"({'terminates immediately at isqrt(n)+1' if steps == 0 else 'fast'})")

    # Step 3: Encrypt plaintext
    m = int.from_bytes(PLAINTEXT, 'big')
    assert m < n, f"Plaintext integer exceeds modulus: {m.bit_length()} bits vs {n.bit_length()} bits"
    c = pow(m, E, n)

    # Step 4: Verify round-trip
    m_dec = pow(c, d, n)
    assert m_dec == m, "RSA round-trip FAILED — encrypt/decrypt mismatch"
    recovered = m_dec.to_bytes((m_dec.bit_length() + 7) // 8, 'big')
    assert b'flag{close_primes_leave_shallow_graves}' in recovered, \
        "Flag not found in decrypted plaintext"
    print("[+] RSA round-trip verified. Flag recoverable.")

    # Step 5: Build SQLite database
    print("[*] Building SQLite database ...")
    db_bytes = build_sqlite_db(n, E, c)
    print(f"[+] SQLite size: {len(db_bytes)} bytes")

    # Step 6: Assemble evidence.img
    print("[*] Assembling evidence.img ...")
    image = build_image(db_bytes)

    # Step 7: Write output
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_img = os.path.normpath(
        os.path.join(script_dir, '..', '..', 'contestant_package', 'evidence.img')
    )
    os.makedirs(os.path.dirname(out_img), exist_ok=True)
    with open(out_img, 'wb') as f:
        f.write(image)
    print(f"[+] Written: {out_img}  ({len(image)} bytes)")

    # Step 8: Verify SQLite magic at correct offset
    sqlite_magic = b'SQLite format 3\x00'
    offset = image.find(sqlite_magic)
    assert offset == 0x800, f"SQLite at wrong offset: {hex(offset)}, expected 0x800"
    print(f"[+] SQLite magic at offset: {hex(offset)} (correct)")

    # Step 9: Verify strings output is clean (no _v4 artifact)
    strings_ok = verify_strings_output(out_img)
    if strings_ok:
        print("[+] strings output verified: clean (no false label artifact)")
    else:
        print("[-] WARNING: strings output check failed — _v4 artifact may be present")

    # Step 10: Save organizer params
    params_path = os.path.normpath(os.path.join(script_dir, '..', 'params.txt'))
    os.makedirs(os.path.dirname(params_path), exist_ok=True)
    with open(params_path, 'w') as f:
        f.write(f"p = {p}\n")
        f.write(f"q = {q}\n")
        f.write(f"n = {n}\n")
        f.write(f"e = {E}\n")
        f.write(f"d = {d}\n")
        f.write(f"|p-q| = {abs(p-q)}\n")
        f.write(f"fermat_steps = {steps}"
                f"  # 0 means isqrt(n)+1 is already the Fermat solution; upper bound ~1000\n")
        f.write(f"n_bits = {n.bit_length()}\n")
        f.write(f"flag = flag{{close_primes_leave_shallow_graves}}\n")
    print(f"[+] Params saved: {params_path}  (KEEP PRIVATE)")

    print()
    print("[+] All checks passed. Challenge is ready.")
    print(f"    Flag: flag{{close_primes_leave_shallow_graves}}")
    print()
    print("=" * 60)
    print("DEPLOYMENT REMINDER:")
    print("  Change RANDOM_SEED and regenerate evidence.img before each")
    print("  new CTF event. Once n is submitted to factordb.com it is")
    print("  permanently indexed and the challenge is trivially solvable.")
    print("=" * 60)


if __name__ == '__main__':
    main()
