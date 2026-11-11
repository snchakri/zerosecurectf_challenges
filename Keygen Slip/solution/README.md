# Keygen Slip — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Keygen Slip — official writeup

**Flag (demo seed):** `zerosecurectf{a_pr1me_m0dulus_is_n0_m0dulus}` (per-instance in production)


## Flaw & attack
RSA security needs N=p*q with two secret primes. Here the keygen used a single prime N, so phi(N)=N-1 is public knowledge, d=e^{-1} mod (N-1), and m=c^d mod N recovers the token with no factoring.

