# Algorithmic Esoteric Bytecode Optimizer — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Brainfuck JIT Transpiler


## 1. Artifact
`dist/program.bf` is a genuine Brainfuck program (22,556 bytes). A leading
comment block uses only letters and spaces (no `+ - < > [ ] . ,`), so it is
inert. The program prints the flag, but it is padded so that a naive
interpreter must execute ~5.1 million operations.


## 2. What makes it slow -- and the fix
- **Dead-weight loop**: a counter cell is set to 255 and a multiply loop adds a
  20,000-long `+` run into a scratch cell (255 x 20000 ~ 5.1M executed `+`),
  which is then cleared with `[-]` and never printed. A naive interpreter grinds
  through all of it; an optimiser erases it.
- **Per-character synthesis**: each flag byte `v` is built in a cell as
  `v = 10*b + r` via a multiply loop `++++++++++[>(+ b)<-]>(+ r).` -- so the
  ASCII bytes never appear literally in the source.

Peephole optimisations that make it instant:
1. run-length collapse of `+ - < >` runs;
2. `[-]` / `[+]` -> set current cell to 0;
3. multiply/copy-loop folding: a flat loop with net pointer move 0 and loop-cell
   delta -1, e.g. `[>+++<-]`, becomes `cell[+1] += 3*cell[0]; cell[0] = 0`.

After folding, every loop is straight-line arithmetic; the dead-weight collapses
to a constant store that is immediately cleared.


## 3. Solver
`solve.py --dist ./dist` parses the program into an IR, applies the three folds
above (falling back to bounded loop execution for anything non-idiomatic), runs
it, and prints the output:

```
python solve.py --dist ./dist
zerosecure{brainfuck_jit_peephole_optimizer_90ff}
```

It contains no flag string and never reads `./flag`. The build script
cross-validates by also running a plain (slow) interpreter and confirming both
emit the same flag (~5.1M dynamic steps).


## 4. Leak safety
The source contains only command characters and an inert letters/spaces comment;
flag bytes are synthesised arithmetically, never written as text. Confirmed by
the leak check.


## 5. Defensive note
Byte-code/esolang evaluators should bound dynamic instruction counts and memory
to avoid denial-of-service via cheap-to-write, expensive-to-run programs.
