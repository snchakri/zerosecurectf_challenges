# The Keystone Seal — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Lift the register VM: `LOADI` gives constants, `MACIN` accumulates coefficients of input bytes, and `CMP` provides target equations.
2. Collect the complete matrix equation `M*x=y (mod 257)` and the required length.
3. Perform modular Gaussian elimination, using multiplicative inverses modulo 257.
4. Check the recovered vector against every original equation, then convert it to bytes.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
