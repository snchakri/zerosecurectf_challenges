# Forensics Note Image — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read `challenge/question.txt` and identify the indicated artifact.
2. Use the decoding or inspection method in the preserved pack notes.
3. Recover the flag from the supplied artifact. This older pack has no separate author solver.

**Verification:** original beginner artifacts retained; independent solution documented during archive review. Original event-only links may no longer respond.

## Concrete solve

1. Inspect PNG metadata and trailing data with `strings` or a hex viewer.
2. Locate the flag stored alongside the image data; displaying the image alone omits this metadata.

```bash
python solution/solve.py
```
