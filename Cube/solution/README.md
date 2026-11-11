# Cube — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Cube — official writeup

**Flag (demo seed):** `zerosecurectf{e3_unp4dded_is_just_a_cube_r00t}` (per-instance in production)


## Flaw & attack
With e=3 and a message short enough that m^3 < N, modular reduction never happens, so c equals m^3 exactly. An integer cube root of c (binary search) recovers m -- no factoring, no private key.

