# Two-Time Pad — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Two-Time Pad — official writeup

**Flag (demo seed):** `zerosecurectf{n3ver_r3use_a_keystr3am_tw1ce}` (per-instance in production)


## Flaw & attack
A stream cipher keystream must never be reused. Here c1 = m1 XOR ks and c2 = m2 XOR ks share ks, and m1 is published, so ks = c1 XOR m1 and m2 = c2 XOR ks reveals the token.

