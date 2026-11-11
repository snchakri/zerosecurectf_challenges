# Vessel of the Void v2 - Full True-Vector Solution Report (Beginner Friendly)

## 0. Important Note

This document is a full spoiler.
Do not distribute this to players during the event.

---

## 1. What you are given

You receive one file:

- `vessel.tar.gz`

If you treat it like a normal archive and only reverse the extracted binary, you will mostly hit decoys.
The real solve depends on both:

1. The outer GZIP container metadata.
2. The inner ELF binary runtime path.

---

## 2. Real idea in one sentence

The true seed is hidden in the GZIP `FEXTRA` field (`VO` subfield), and that seed must be passed to:

- `./void mirror --seed <seed_hex>`

Then the binary derives the correct key and prints the real flag.

---

## 3. Prerequisites

Use Linux (or WSL Ubuntu) with:

- `python3`
- `tar`
- standard shell tools

No advanced RE tools are required for the true path.

---

## 4. Step-by-step solve path

## Step 1: Verify artifact integrity

Run:

```bash
sha256sum vessel.tar.gz
```

Compare with organizer checksum if provided.

Why this matters:
If the artifact was changed, the seed and ciphertext relationship may break.

---

## Step 2: Extract and observe the decoy behavior

Run:

```bash
mkdir -p work
cd work
tar -xzf ../vessel.tar.gz
chmod +x void
./void mirror
```

Expected decoy-like output includes a false flag and breadcrumb taunt, for example:

- `zerosecurectf{you_broke_the_mirror_but_discarded_its_frame}`
- `Truth does not survive extraction. You broke the mirror but discarded its frame.`

Why this matters:
The challenge intentionally nudges you to inspect the outer archive format.

---

## Step 3: Read GZIP header and extract VO payload

Go back to folder containing `vessel.tar.gz`, then run this Python snippet:

```bash
python3 - << 'PY'
import struct
from pathlib import Path

p = Path('vessel.tar.gz')
d = p.read_bytes()

if d[:2] != b'\x1f\x8b':
    raise SystemExit('Not a gzip file')

flg = d[3]
print('FLG =', hex(flg))
if (flg & 0x04) == 0:
    raise SystemExit('FEXTRA not set')

xlen = struct.unpack_from('<H', d, 10)[0]
pos = 12
end = pos + xlen

seed = None
hmac16 = None

while pos + 4 <= end:
    sid = d[pos:pos+2]
    slen = struct.unpack_from('<H', d, pos+2)[0]
    payload = d[pos+4:pos+4+slen]
    if sid == b'VO':
        if len(payload) != 48:
            raise SystemExit(f'VO payload length mismatch: {len(payload)}')
        seed = payload[:32]
        hmac16 = payload[32:]
        break
    pos += 4 + slen

if seed is None:
    raise SystemExit('VO subfield not found')

print('VO seed (32 bytes hex):', seed.hex())
print('VO hmac (16 bytes hex):', hmac16.hex())
PY
```

You should see:

1. `FLG` includes `0x4`.
2. A valid `VO` subfield.
3. A 32-byte seed in hex.

---

## Step 4: Use extracted seed with the hidden true path

Use the seed hex from Step 3 and run:

```bash
./work/void mirror --seed <PASTE_64_HEX_CHARS_HERE>
```

Example format (not real value):

```text
./work/void mirror --seed 0123abcd...<64 total hex chars>
```

Expected output:

- `zerosecurectf{caught_final_void}`

That is the real flag.

---

## 5. Why this works (simple explanation)

Inside the binary, when `mirror --seed` is provided:

1. It parses your hex seed into 32 bytes.
2. It reads its own executable on disk via `/proc/self/exe`.
3. It parses ELF sections and hashes `.text` with SHA-256.
4. It runs PBKDF2-HMAC-SHA256 with:
   - password/input key = seed from archive
   - salt = `.text` hash
5. It derives AES key + IV.
6. It decrypts embedded ciphertext.
7. Decrypted plaintext is the true flag.

If seed is wrong, decryption fails and you do not get the real flag.

---

## 6. Common mistakes (and fixes)

## Mistake A: Only reversing the extracted binary

Symptom:
You keep finding plausible but wrong `zerosecurectf{...}` outputs.

Fix:
Inspect raw `vessel.tar.gz` bytes and parse `FEXTRA`.

## Mistake B: Using wrong seed size

Symptom:
Binary says invalid seed format.

Fix:
Seed must be exactly 32 bytes = 64 hex characters.

## Mistake C: Copying the full 48-byte VO payload as seed

Symptom:
`mirror rejected this seed`.

Fix:
Use only first 32 bytes of VO payload as seed.
The final 16 bytes are HMAC fragment, not seed input.

## Mistake D: Running on unsupported/non-Linux runtime

Symptom:
Path logic around `/proc/self/exe` behaves unexpectedly.

Fix:
Run inside Linux/WSL Ubuntu.

---

## 7. One-command reference solve (optional)

If organizer includes helper script:

```bash
python3 ../builder/solve.py --artifact ../vessel.tar.gz
```

This automates:

1. VO extraction from GZIP header.
2. Seed passing to binary.
3. Final flag recovery.

---

## 8. Final result

Real flag:

- `zerosecurectf{caught_final_void}`

---

## 9. Learning takeaway for beginners

This challenge teaches a key CTF lesson:

Do not assume the extracted payload is the whole truth.
Container metadata can be the real key material.

In short:

- Archive format knowledge + binary runtime analysis > binary-only reversing.
