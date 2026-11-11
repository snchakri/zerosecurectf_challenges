# NULL STREAM — Organizer Deployment Notes

## Challenge Summary

| Field | Value |
|---|---|
| Category | Crypto + Reverse Engineering |
| Difficulty | Hard |
| Deployment | Offline (no server needed) |
| Estimated solve time | 45–90 minutes |
| Flag | `flag{static_is_just_a_keystream_waiting_to_be_read}` |

---

## Files to Distribute (contestant_package/)

| File | How it's produced |
|---|---|
| `encode` | Compiled from `source/encode.c` on Linux (see below) |
| `transmission.null` | Run `python3 source/generate_transmission.py` |
| `README.md` | Already written — no changes needed |

---

## Building the Binary

Must be compiled on a Linux x86-64 machine.
The binary must be stripped before distribution.

```bash
gcc -O2 -o encode source/encode.c
strip encode
cp encode contestant_package/encode
```

Verify the right strings are surfaced after stripping:
```bash
strings encode | grep -E "NULL_STREAM_V1|NULLSTRM|usage"
# Expected output:
# NULL_STREAM_V1
# usage: %s <input> <o>
# NULLSTRM
```

If those strings are missing, the binary will not be solvable via the
strings recon step. Do not distribute without verifying this.

---

## Generating transmission.null

```bash
cd organizer_only/source
python3 generate_transmission.py
```

Expected output:
```
[+] Generated: .../contestant_package/transmission.null
[+] Total size : 384 bytes
[+] Nonce (hex): a3f7c2d841b9e605
[+] Seed       : 0xdd244ee2
[+] Verification passed.
```

If verification fails, the Python LFSR implementation has drifted from
the C source. Both must produce identical keystreams for the same nonce.

---

## Verifying the Challenge (end-to-end test)

```bash
python3 organizer_only/solve.py contestant_package/transmission.null
```

Expected output ends with:
```
flag{static_is_just_a_keystream_waiting_to_be_read}
```

Also test the binary manually:
```bash
echo -n "TESTINPUT" > test.txt
./encode test.txt test.enc
# Confirm test.enc is 25 bytes (9 plaintext + 16 header)
xxd test.enc | head
# Should show NULLSTRM at offset 0
```

---

## Difficulty Breakdown (for judges)

| Step | Difficulty | Notes |
|---|---|---|
| file + strings recon | Easy | Any CTF player does this first |
| xxd header read | Easy | NULLSTRM visible in plaintext |
| Load in radare2 / dynamic path | Medium | Expected tool usage |
| Recognize LFSR from assembly | Hard | Main difficulty spike |
| Galois vs Fibonacci variant | Hard | Second spike — most players know Fibonacci LFSR |
| Extract TAP_MASK + seed derivation | Medium | Visible in binary once player knows where to look |
| Python decryptor | Easy | ~15 lines once parameters known |

Well-balanced Hard. Two complementary attack angles are available.
Path A (full RE): player disassembles encode, reads the Galois LFSR loop,
extracts TAP_MASK (0x80200003) and derive_seed, and reproduces the keystream.
Path B (dynamic + crypto): player encrypts known plaintext to extract a raw
keystream, runs Berlekamp-Massey to confirm the 32-bit LFSR and recover the
characteristic polynomial, then converts it to the Galois tap mask via the
reciprocal polynomial. Path B still requires RE to discover the derive_seed
function (XOR-fold of the nonce halves) — it cannot be inferred from the
keystream alone. The two paths are complementary: Path B narrows the cipher
structure; Path A provides the seed derivation needed to target transmission.null.

---

## Common Mistakes to Watch For

- Player strips the header incorrectly (decrypts from byte 0, gets garbage)
  → First 16 bytes are header, ciphertext starts at byte 16

- Player implements Fibonacci LFSR instead of Galois (wrong feedback order)
  → Hint 3 specifically warns "Galois, not Fibonacci" and "shift first"

- Player applies BM polynomial directly as Galois mask without reversing
  → BM returns Fibonacci (external) form; Galois mask needs the reciprocal
     polynomial (reverse C[1:] before building the mask)

- Player on Windows tries to run encode natively (won't work — Linux ELF)
  → README says "use WSL or a VM"

- Player tries to factor the keystream or treat it as RSA
  → No numerical patterns; this is a stream cipher

---

## Platform Upload Checklist

- [ ] `encode` binary confirmed stripped (Linux x86-64)
- [ ] `transmission.null` generated and verified via solve.py
- [ ] `README.md` contains no hints about cipher type
- [ ] Category set to: Crypto + Reverse Engineering
- [ ] Difficulty set to: Hard
- [ ] Hint 1 unlocked at start (0 pts)
- [ ] Hints 2–4 require point deduction (20 / 40 / 60 pts)
- [ ] Flag confirmed: `flag{static_is_just_a_keystream_waiting_to_be_read}`
