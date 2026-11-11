# Staged Hint Ladder: Rule 30 Lattice Warden

### Hint Level 1 (orientation)
Disassemble `dist/checker.pyc` (`marshal` + `dis`, or a decompiler). The warden
reads your key, spreads its *bits* across a one-dimensional lattice, and marches
it forward a fixed number of generations under Rule 30 with **open** (non-
wrapping) boundaries -- the cells past each end are treated as 0. It then checks
the final lattice against one embedded block of bytes. There is no stored key.

### Hint Level 2 (reframe)
Rule 30 is `new[i] = left XOR (center OR right)`. People call it irreversible
because information spreads, but look closely at the direction: a cell's new
value pulls its *left* neighbour's old value out of the expression. Rearrange
the update to isolate that left neighbour. Notice the warden embeds a *second*,
much shorter block as well -- one bit per generation. Ask what single cell per
row you would need to turn the rearranged equation into a left-ward sweep.

### Hint Level 3 (strong nudge)
From `new[i] = L XOR (C OR R)` you get `L = new[i] XOR (C OR R)`; i.e. for a row
at time t, `cell[j] = next[j+1] XOR (cell[j+1] OR cell[j+2])` with the off-end
cell = 0. Given the *entire* next row and the single **rightmost** cell of the
current row, you can fill the current row right-to-left with no search. The
short embedded block is exactly that rightmost-cell column, one entry per
generation. Seed each reverse step with it, walk all the generations back to
row 0, and read the bits off as bytes.

---
*Note: Crux Floor invariant -- the core reverse-engineering insight is never
handed out completely; each hint restores a reasoning handle, not the answer.*
