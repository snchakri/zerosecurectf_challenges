# Rule 30 Dynamical System Reversal — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Rule 30 Lattice Warden (rev_07)


## Flag
`zerosecure{rule30_1d_cellular_automaton_step_82bd}`


## Design summary
`dist/checker.pyc` is a CPython 3.13 module. It reads a candidate key on stdin,
lays the key's bits (MSB-first per byte) across a one-dimensional lattice of
`N = 8 * len(key)` cells, and evolves it `G = 104` generations under Wolfram's
**Rule 30** with *open* boundaries (ghost cells past either end are 0):

```
new[i] = left XOR (center OR right)
```

It bakes in two blobs (plain `bytes` constants in the marshalled bytecode):

- `FINAL` -- the packed lattice after G generations (N bits -> N/8 bytes);
- `REDGE` -- the "integrity column": the single **rightmost** cell of the
  lattice at the start of each generation, one bit per generation (G bits).

The module accepts iff the forward run of the candidate reproduces **both**
`FINAL` and `REDGE`. The flag (the seed row, generation 0) is never stored.


## Why the naive reading fails
Rule 30 is the textbook chaotic/irreversible elementary CA; from a final row
alone you cannot recover a seed, and the seed space here is 2^400, far past any
brute force. `strings`/grep reveal nothing: only the transformed `FINAL` and the
`REDGE` column are present, never the key in any plain/hex/base64/reversed form.


## The twist (intended solution)
Rule 30 moves information strictly **leftward**: a new cell is `left XOR (center
OR right)`, so the *left* neighbour can be isolated. Rearranged for a row at
time `t` given the next row `next = row(t+1)`:

```
cell[j] = next[j+1] XOR (cell[j+1] OR cell[j+2])     (cell past the end = 0)
```

This is a right-to-left sweep: computing `cell[j]` needs only `next[j+1]` (known)
and cells to the right at the same time (already computed). The only cell the
sweep cannot produce is the **rightmost** one, `cell[N-1]` -- and that is exactly
what `REDGE` supplies for each generation. So:

1. Pull `FINAL` and `REDGE` out of the `.pyc` constants (`marshal.loads` after
   the 16-byte header, recurse `co_consts`). `N = 8*len(FINAL)`, `G = 8*len(REDGE)`
   (G was chosen a multiple of 8, so the column packs with no padding).
2. Starting from `row = FINAL`, for `t = G-1 .. 0`: set `cur[N-1] = REDGE[t]`,
   then fill `cur[j] = row[j+1] XOR (cur[j+1] OR cur[j+2])` for `j = N-2 .. 0`.
   Replace `row` with `cur`.
3. After G reversals, `row` is the seed. Pack the bits (MSB-first) into bytes --
   that is the flag.

The reversal is fully deterministic and O(N*G); no search, no brute force.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{rule30_1d_cellular_automaton_step_82bd}
```
`solve.py` reads only `dist/checker.pyc`, extracts the two blobs, runs the
reverse sweep, and prints the flag. It contains no flag string and never reads
the `flag` file.


## Rebuild (reproducible from ./flag)
```
python src/build.py      # forward-runs the flag, self-tests the reversal,
                         # emits dist/checker.pyc (FINAL + REDGE, never the key)
```


## References
- Wolfram, S. (1983). *Statistical mechanics of cellular automata*, Rev. Mod. Phys. 55, 601.
- Wolfram, S. (2002). *A New Kind of Science*, Wolfram Media -- Rule 30 and the
  left/right flow of information in elementary CAs.


## Defense note
A chaotic CA is reverse-engineering friction, not a cryptographic control; here
a leaked boundary column collapses the whole scheme. Never gate a secret behind
an invertible transform of itself -- use an authenticated KDF/KEM.
