# The Mandala Sigils — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

1. For each flag position, convert every directed graph into a set of `(source,destination)` arcs.
2. Intersect the five sets. The unique common arc gives the high and low hex nibbles of that byte.
3. Join the bytes in the published position order and decode the flag.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.

## Event/source difference

The solver derives its answer from the preserved artifact. Its output differs from, or has no matching entry in, the CTFd `accepted_flags.txt` snapshot. Both are retained as historical evidence; the expected event answer is not silently substituted into the solver.
