# The Hall of Wards — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. Use the public flag prefix and closing brace to fix known secret bytes; center the remaining ASCII bytes around 96.
2. Subtract the known contribution from `b`. Embed the remaining small secret and error into an integer lattice with modulus multiples.
3. Use LLL to find the embedded short vector. Restore the centered bytes and verify that **every** residual error lies in `−1..1`.
4. Decode the resulting complete secret byte vector.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
