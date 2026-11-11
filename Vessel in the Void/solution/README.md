# Vessel in the Void — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Verify the GZIP artifact checksum.
2. Parse the GZIP FEXTRA data and recover the seed stored in the `VO` subfield.
3. Extract the ELF and run `./void mirror --seed <seed_hex>`.
4. Compare the recovered flag with the result described in `SOLUTION_REPORT.md`; the other binary paths are decoys.

Author procedures and reference material:

- [SOLUTION_REPORT.md](SOLUTION_REPORT.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

The author solver reads the GZIP VO subfield, extracts its 32-byte seed, and invokes the extracted ELF with `mirror --seed`. It uses a temporary extraction directory.

```bash
python solution/solve.py
```
