# Reverse Tiny Lock — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Read `challenge/question.txt` and identify the indicated artifact.
2. Use the decoding or inspection method in the preserved pack notes.
3. Recover the flag from the supplied artifact. This older pack has no separate author solver.

**Verification:** original beginner artifacts retained; independent solution documented during archive review. Original event-only links may no longer respond.

## Concrete solve

1. Run `strings challenge/tiny_lock` or inspect its constant strings in a disassembler.
2. Locate the flag-formatted password used by the checker.
3. Supply it to the program to confirm acceptance.

```bash
python solution/solve.py
```

The supplied `tiny_lock` is a shell script. Concatenate its `p1` through `p5` variables in numeric order and enter that string. The solver also runs the checker to confirm acceptance.
