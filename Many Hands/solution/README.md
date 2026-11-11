# Many Hands — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Many Hands — official writeup

**Flag (demo seed):** `zerosecurectf{a_kn0wn_crib_unwinds_th3_x0r_k3y}` (per-instance in production)


## Flaw & attack
The record is XORed with a short repeating key. Because the plaintext starts with the fixed header 'ACTIVATION-TOKEN=', XORing the ciphertext against that header yields the key over those positions; the smallest period L that stays consistent across the 17-byte header is the key length, and the full key decrypts the rest, exposing the token after '='.

