# The Suspicious Lookup — solution

1. Apply the `dns` filter and inspect query names.
2. The unusual query begins `zerosecurectf-dns-query-reveals-secret`. Convert the meaningful hyphen-separated body to underscores and wrap it in the required flag format.

Automated recovery from the original capture:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

Compare the derived result with `accepted_flags.txt`.
