# The Fragmented Query — solution

1. Inspect DNS questions and locate the `part1`, `part2`, and `part3` labels.
2. Sort by the numeric part identifier, then join the fragments in that order. Treat the `zerosecurectf` fragment as the prefix, and convert body hyphens to underscores.

Automated recovery from the original capture:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

Compare the derived result with `accepted_flags.txt`.
