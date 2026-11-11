# The Ash Gate Rings — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Write the plaintext as `H*256^L+x`, where the decree header `H` and unknown suffix length `L` are public.
2. Build the monic modular polynomial `(H*256^L+x)^3−c`. The 29-byte unknown is small enough for univariate Coppersmith recovery.
3. Construct the integer lattice from `N^(m−i)*x^j*f(x)^i` with `m=2`, reduce with LLL, and extract an integer root from the short polynomials.
4. Verify the root by re-encrypting the complete header-plus-suffix plaintext. Decode only the recovered suffix.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
