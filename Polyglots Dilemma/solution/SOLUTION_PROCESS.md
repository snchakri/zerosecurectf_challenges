# ch3_polyglots_dilemma - Solution Process

## Intended path (static)

1. Recognize PyInstaller bundle signatures.
2. Extract embedded archive.
3. Recover .pyc files.
4. Decompile bytecode.
5. Reconstruct password logic.

## Alternate path (dynamic)

- instrument runtime checks and observe transformed input comparisons.

## Expected tooling

- pyinstxtractor
- decompyle3/uncompyle6
- basic Python scripting
