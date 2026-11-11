# Simulation — Archive Forensics — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. List archive entries before extraction and identify the simulated recursive archive layer.
2. Inspect the archive metadata and player documents; the original hint and complete simulation notes are retained in this folder.
3. Follow the author notes to isolate the real payload from the simulated expansion decoy.

Author procedures and reference material:

- [Hints - Notesnook.pdf](Hints%20-%20Notesnook.pdf)
- [SIMULATION-ZIPBOMB - Notesnook.pdf](SIMULATION-ZIPBOMB%20-%20Notesnook.pdf)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Exact recovery

1. Open the outer ZIP without recursively expanding nested archives.
2. Find `artifact_0042.txt` in the second bundle under `src`.
3. Extract the encoded value following `::`.
4. Base64-decode it, then apply ROT13 to obtain `zerosecurectf{simulation_flag}`.

Run `python solution/solve.py`. The PDF notes confirm both the file and the decoding order.
