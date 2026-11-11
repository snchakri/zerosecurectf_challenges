# Staged Hint Ladder: Brainfuck JIT Transpiler

### Hint Level 1 (Orientation)
Only the eight characters `+ - < > [ ] . ,` are executed; everything else
(including the header comment, which contains no command characters) is ignored.
A straight interpreter is correct but slow here: the program deliberately runs
several million operations.

### Hint Level 2 (Reframe)
Apply peephole optimisations before executing:
- run-length collapse: a run of N `+` (or `-`, `>`, `<`) is one add/move of N;
- clear loops: `[-]` and `[+]` set the current cell to 0;
- the big "dead-weight" loop multiplies a counter by a long `+` run into a
  scratch cell and then clears it -- pure fodder for the above folds.

### Hint Level 3 (Strong Nudge)
Also fold copy/multiply loops: a flat loop whose body has net pointer movement 0
and decrements the loop cell by 1 (e.g. `[>+++<-]`) is equivalent to
`cell[+offset] += 3 * cell[0]; cell[0] = 0`. With run-length + clear + multiply
folding, every loop becomes straight-line arithmetic and the program prints its
output in microseconds.

---
*Note: Crux Floor invariant: the optimisation families are named; implementing a
correct folding interpreter/transpiler is left to the solver.*
