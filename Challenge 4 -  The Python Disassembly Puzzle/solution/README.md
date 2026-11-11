# Challenge 4: The Python Disassembly Puzzle — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Build the original reference artifact with `python build.py` from `solution/` if a binary was not preserved.
2. Inspect the reconstruction/checking function in the compiled artifact.
3. Apply the inverse transformation documented in the source and run `verify.py` to compare the recovered answer.

**Verification:** source prototype archived; release binary availability recorded in catalog. Original event-only links may no longer respond.

## Original build limitation

The generator explicitly requires Python 3.10 or 3.9. It disassembles a function that loads its payload from a global variable, while the verifier expects that payload in a `LOAD_CONST`. The local source therefore has a generator/verifier mismatch, and no release transcript was found. The prototype source is preserved without claiming a playable handout.
