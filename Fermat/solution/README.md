# Fermat — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Fermat — official writeup

**Flag (demo seed):** `zerosecurectf{cl0se_pr1mes_f4ll_t0_f3rmat}` (per-instance in production)


## Flaw & attack
N = p*q with p and q only a few hundred apart, so a = ceil(sqrt(N)) is barely above sqrt(N); a few steps of Fermat's method (test a^2 - N for a perfect square) split N. Then phi = (p-1)(q-1), d = e^{-1} mod phi, and m = c^d mod N recovers the token.

