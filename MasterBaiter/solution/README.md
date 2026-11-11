# MasterBaiter — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Inspect the validation logic rather than submitting the first flag-shaped string.
2. Recover the real input from the byte transformation in the checker.
3. Run the program with that value and compare against `MasterBaiter_WRITEUP.md`.

Author procedures and reference material:

- [MasterBaiter_WRITEUP.md](MasterBaiter_WRITEUP.md)
- [fishoverview.md](fishoverview.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

1. Reverse `chk`: it accepts when `sum(input[i] * (i+1)) % 1337 == 420`.
2. Enumerate short printable strings until the condition holds.
3. Supply one accepted string to the binary. The successful branch decodes its real flag; the visible common-fish string is a decoy.
4. The wrapper finds a three-character input and runs the supplied binary.

```bash
python solution/solve.py
```

## Reproduced checker mismatch

The preserved binary accepts `!!k` and reaches the legendary-fish branch, but prints `zdplw` followed by malformed decoded text, rather than the flag in the author writeup. The documented encoded array and XOR loop also disagree with the stated answer. The binary is preserved unchanged; the solve script reproduces the accepted-input path, and the original claimed flag remains in `MasterBaiter_WRITEUP.md`.
