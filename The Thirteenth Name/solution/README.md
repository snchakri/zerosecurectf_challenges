# The Thirteenth Name — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Rewrite each signature as `k_i = (r_i/s_i)*d + h_i/s_i (mod n)`. Each nonce is bounded by `2^200`.
2. Construct a scaled Hidden Number Problem lattice. Its short residual coordinates are the small nonces, while the last coordinate carries the private scalar.
3. Use LLL and closest-vector recovery, then check every recovered nonce against the published bound and every signature equation. Decode the private scalar as ASCII.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
