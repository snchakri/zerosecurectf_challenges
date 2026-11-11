# Regular Expression Constraint Satisfaction — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Hexagonal Regex Crossword


## 1. Artifact
`dist/crossword_patterns.json` describes a three-axis regex crossword over a
6x9 grid (54 cells). It lists the `alphabet` and 29 `lines`: 6 rows, 9 columns,
and 14 `\`-diagonals (cells grouped by `col - row`). Each line gives the ordered
`[row, col]` cells it covers and a `pattern` that the concatenated line string
must fully match. The grid read row by row (top to bottom, left to right) is the
flag.


## 2. Structure of the constraints
Every line pattern is `^<class><class>...$`, a concatenation of character
classes (one per cell). Each cell lies on three lines -- row, column, diagonal.
By construction the decoy characters in the three axes are drawn from pairwise
disjoint pools (row: lowercase; column: digits/symbols; diagonal: uppercase),
and every class also contains the cell's true character. Therefore the
intersection of any two axes' classes at a cell is exactly the true character,
which makes the whole puzzle have a single solution. (A solver does not need to
know this; it falls out of constraint propagation.)


## 3. Intended solution
Treat it as a CSP: variables = cells over the alphabet, constraints = "line
string fully matches its regex". Two standard engines work:
- **Automata**: compile each pattern to an NFA/DFA and solve the product (the
  regex-crossword classic), or
- **SMT**: assert each line's regex membership in Z3's string theory and read
  the model.

A plain backtracking search with forward checking also suffices: when assigning
a cell, for each line through it, run an NFA reachability pass that allows a
singleton for assigned cells and the full domain for unassigned cells; if any
line can no longer reach an accept state, backtrack. Because three axes cross at
each cell, the domains collapse to a single character almost immediately and the
search is effectively linear.


## 4. Solver
`solve.py --dist ./dist` ships a compact regex engine (classes with
ranges/negation, `.`, concatenation, alternation, grouping, `* + ? {m} {m,n}`,
full-match anchoring) that compiles each pattern to a Thompson NFA, then solves
the crossword by backtracking + forward checking and verifies the solution is
unique before reading it out:

```
python solve.py --dist ./dist
zerosecure{regex_crossword_satisfying_assignment_41bc}
```

It contains no flag string and never reads `./flag`.


## 5. Leak safety
Only the regex patterns and geometry are published; the flag characters appear
only as one option among the decoys in each class, never as a contiguous string.
Confirmed by the leak check (no plain/hex/base64/reversed/strings hit).


## 6. Defensive note
Unrelated to deployment security; the "lesson" is purely that intersecting
regular languages across multiple axes pins a unique word -- the automata-product
view that also underlies ReDoS analysis.
