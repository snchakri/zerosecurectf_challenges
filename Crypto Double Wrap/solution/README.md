# Crypto Double Wrap — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read `challenge/question.txt` and identify the indicated artifact.
2. Use the decoding or inspection method in the preserved pack notes.
3. Recover the flag from the supplied artifact. This older pack has no separate author solver.

**Verification:** original beginner artifacts retained; independent solution documented during archive review. Original event-only links may no longer respond.

## Concrete solve

1. Base64-decode `data.txt` to a string of hexadecimal digits.
2. Decode the hex bytes as UTF-8 to obtain the flag.

```bash
python solution/solve.py
```
