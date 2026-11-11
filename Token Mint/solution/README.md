# Token Mint — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Token Mint — official writeup

**Flag (demo seed):** `zerosecurectf{an_lcg_is_n0t_a_s3cure_t0ken_s0urce}` (per-instance in production)


## Flaw & attack
With modulus m known and outputs x0..x3 given, a = (x2 - x1)*(x1 - x0)^{-1} mod m and c = x1 - a*x0 mod m recover the generator, so the next token x4 = a*x3 + c mod m is fully determined. Non-cryptographic generators must never mint security tokens (CWE-338).

