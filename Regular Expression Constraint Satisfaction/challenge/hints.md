# Staged Hint Ladder: Hexagonal Regex Crossword

### Hint Level 1 (Orientation)
`crossword_patterns.json` gives a 6x9 grid, the `alphabet` a cell may hold, and
a list of `lines`. Each line names the cells it covers (as `[row, col]` pairs, in
order) and a `pattern` the concatenated line string must FULLY match. Every cell
participates in three lines: its row, its column, and a `\`-diagonal (cells with
the same `col - row`).

### Hint Level 2 (Reframe)
Model it as constraint satisfaction: each cell is a variable over the alphabet;
each line is a regular-language constraint over its cells. Because three axes
cross at every cell, the per-cell domain shrinks fast once you intersect the
constraints coming from all three directions.

### Hint Level 3 (Strong Nudge)
Compile each pattern to a DFA/NFA and solve the product constraint, or encode the
whole thing for an SMT solver (Z3's string/sequence theory handles regex
membership directly). A backtracking search with forward-checking -- at each
assignment, test whether every line through that cell can still be completed to a
match -- converges immediately because the puzzle is tightly interlocked. Read
the solved grid row by row for the flag.

---
*Note: Crux Floor invariant: the solving model is named; the engine and the final
read-out are left to the solver.*
