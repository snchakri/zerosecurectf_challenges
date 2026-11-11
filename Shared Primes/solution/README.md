# Shared Primes — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Shared Primes — official writeup

**Flag (demo seed):** `zerosecurectf{shar3d_pr1mes_d1e_t0_one_gcd}` (per-instance in production)


## Flaw & attack
A device with a poor RNG generated two moduli that happen to share a prime p. Then gcd(N1,N2)=p (computable instantly even for 1024-bit N), q=N1/p, phi=(p-1)(q-1), d=e^{-1} mod phi, m=c^d mod N1. This is exactly the real-world weak-key incident (Lenstra et al. 2012).

