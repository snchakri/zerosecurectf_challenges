# ENTROPY GRAVE — Organizer Deployment Notes

## Challenge Summary

| Field | Value |
|---|---|
| Category | Crypto + Forensics |
| Difficulty | Hard |
| Deployment | Offline (no server needed) |
| Estimated solve time | 60–120 minutes |
| Flag | `flag{close_primes_leave_shallow_graves}` |

---

## Files to Distribute (contestant_package/)

| File | How it's produced |
|---|---|
| `evidence.img` | Run `python3 source/generate_image.py` (see below) |
| `README.md` | Already written — no changes needed |

---

## Generating evidence.img

Requires Python 3.8+ and sympy.

```bash
pip install sympy
cd organizer_only/source
python3 generate_image.py
```

Expected output:
```
[+] |p - q| = <value> (< 65536)
[+] Fermat's factorization: 0 iterations (terminates immediately at isqrt(n)+1)
[+] RSA round-trip verified. Flag recoverable.
[+] SQLite magic at offset: 0x800 (correct)
[+] strings output verified: clean (no false label artifact)
[+] Modulus n verified: exactly 1024 bits
[+] Written: .../contestant_package/evidence.img
[+] Params saved: .../organizer_only/params.txt (KEEP PRIVATE)
[+] All checks passed. Challenge is ready.
```

**Note on "0 iterations":** This is correct and expected. Fermat's algorithm
starts at `a = isqrt(n) + 1`. For this key pair that value of `a` is already
the solution (b² = a²−n is a perfect square on the first try). Upper bound
for any key pair this script generates is approximately 1000 iterations.

If you see "RSA round-trip failed" or "Fermat did not converge", do not
distribute the image. The generation script validates everything internally.

Keep params.txt private. It contains p, q, and d.

---

## Verifying the Challenge (end-to-end test)

```bash
python3 organizer_only/solve.py contestant_package/evidence.img
```

Expected output ends with:
```
flag{close_primes_leave_shallow_graves}
```

---

## What Contestants Will Find (Step-by-Step)

```
$ file evidence.img
evidence.img: data                    <- not a filesystem, must scan

$ strings evidence.img
SECURE-WIPE v2.3 INITIATED
Process terminated: power failure at 2.3%
...
WARNING: prime difference unusually small -- flagged for review  <- KEY LINE
...
config.db relocated to secondary partition [sector 0x800]  <- tells where DB is
...
operations_key_q1                          <- clean label, no suffix noise
RSA-1024. Low-entropy key gen -- nexum-keygen v0.4.1. See device log.
operations_report_q1.txtRSA-1024-RAW

$ binwalk evidence.img
DECIMAL       HEXADECIMAL     DESCRIPTION
2048          0x800           SQLite 3.x database, ...

$ binwalk -e evidence.img
# Creates _evidence.img.extracted/800 (the SQLite file)

$ sqlite3 _evidence.img.extracted/800
sqlite> .tables
encrypted_records  key_config
sqlite> SELECT label, e, key_size, notes FROM key_config;
operations_key_q1|65537|1024|RSA-1024. Low-entropy key gen...
sqlite> SELECT hex(modulus) FROM key_config;
<256-char hex string — the 1024-bit modulus n>
sqlite> SELECT algorithm, length(payload) FROM encrypted_records;
RSA-1024-RAW|128
sqlite> SELECT hex(payload) FROM encrypted_records;
<256-char hex string — the raw ciphertext c>
```

Then Fermat's factorization on n, reconstruct d, decrypt.

---

## WSL / binwalk Fallback

If a contestant is on WSL and binwalk extraction fails, this Python
one-liner extracts the database without binwalk:

```python
data = open('evidence.img','rb').read()
magic = b'SQLite format 3\x00'
off = data.find(magic)
open('config.db','wb').write(data[off:])
```

This works because the SQLite database is the last section in the image.
The README hints this with "standard forensic tools work on it."

---

## Difficulty Breakdown (for judges)

| Step | Difficulty | Notes |
|---|---|---|
| file + strings on image | Easy | Standard forensic recon |
| binwalk extraction | Easy-Medium | Well-known tool; Python fallback provided |
| sqlite3 queries | Easy | Standard tool, columns referenced by name |
| Connecting log → Fermat's | Hard | Main spike — requires research/knowledge |
| Implementing Fermat's | Medium | Algorithm is ~8 lines once found |
| RSA decrypt from integers | Medium | hex(modulus)/hex(payload) → int(hex,16) → pow(c,d,n) |

Well-balanced Hard. The forensics pipeline is straightforward.
The difficulty is concentrated at one conceptual leap (the log clue → attack).
A player who reads the log carefully and searches intelligently will find it.

---

## Common Mistakes to Watch For

- Player tries to mount evidence.img as a filesystem
  → file shows "data". strings reveals wipe header immediately.
  → Hint 1 corrects this without spoiling.

- Player factordb's the modulus (searches online factoring databases)
  → Key is freshly generated — not in any database at first deployment.
  → No shortcut on first run. See regeneration warning below.

- Player tries common modulus or other RSA attacks
  → Only one key; common modulus does not apply.
  → The log clue specifically points to prime generation flaw.

- Player extracts hex(payload) but converts it incorrectly
  → Payload is a raw BLOB. Use: c = int(hex_string, 16)
  → No base64 involved — ciphertext is stored as raw bytes.

- Player extracts hex(modulus) but converts it incorrectly
  → Same: n = int(hex_string, 16)

- Player sees "Factored in 0 iterations" and thinks solve.py is broken
  → This is correct. isqrt(n)+1 is already the Fermat solution for this
     key pair. 0 iterations means it solved on the very first candidate.

---

## ⚠️  factordb Reuse Warning

**Regenerate evidence.img before every new CTF event.**

The modulus `n` embedded in evidence.img is fixed per deployment.
If any participant (or anyone who later downloads the challenge files)
submits `n` to [factordb.com](https://factordb.com), the factors p and q
are indexed permanently and publicly. Any future use of the same
evidence.img is then instantly solvable by looking up `n` on factordb —
no Fermat's factorization required, no cryptographic work at all.

**How to regenerate safely:**
1. Change `RANDOM_SEED` in `generate_image.py` to any new value.
2. Run `python3 generate_image.py` from `organizer_only/source/`.
3. Verify with `python3 organizer_only/solve.py contestant_package/evidence.img`.
4. Distribute the new `evidence.img` only — never the params.txt.

---

## Platform Upload Checklist

- [ ] `RANDOM_SEED` changed from previous deployment (if reusing challenge)
- [ ] evidence.img regenerated and verified via solve.py
- [ ] params.txt confirmed private (NOT in contestant_package)
- [ ] README.md contains no hints about RSA or Fermat
- [ ] Category set to: Crypto + Forensics
- [ ] Difficulty set to: Hard
- [ ] Hint 1 unlocked at start (0 pts)
- [ ] Hints 2–4 require point deduction (20 / 40 / 60 pts)
- [ ] Flag confirmed: `flag{close_primes_leave_shallow_graves}`
