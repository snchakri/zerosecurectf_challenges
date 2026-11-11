# Lopsided — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Lopsided — official writeup

**Flag (demo seed):** `zerosecurectf{unbal4nced_pr1mes_fall_t0_rho}` (per-instance in production)


## Flaw & attack
RSA needs balanced primes. Here one factor is only ~36 bits, so Pollard's rho finds it in on the order of 2^18 iterations; then q=N/p, phi=(p-1)(q-1), d=e^{-1} mod phi decrypts the token.

