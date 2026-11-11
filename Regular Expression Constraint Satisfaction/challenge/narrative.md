# Challenge: Hexagonal Regex Crossword (misc_07_regex_crossword_hexagonal)

**Category:** Miscellaneous
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Automata Reality

---

## Scenario & Objective
Set into the floor of Doom's chancery is a lattice of blank tiles, and around its
three axes run engraved sigils -- patterns that every line of tiles must obey at
once. The citadel's archivists use it as a lock: only one way of inscribing the
tiles satisfies every sigil along every row, every column, and every slanting
diagonal. CICADA3301 copied the sigils onto paper. Now the grid must be filled.

Three families of constraints pull on each tile simultaneously; no single sigil
decides a tile alone. Solve the system, read the grid the way the archivists do
-- row by row, top to bottom -- and the lock's secret spells itself out.

## Provided Files
- `dist/crossword_patterns.json` -- the grid geometry (6 rows x 9 columns), the
  alphabet of permitted tile characters, and the regular expression each line
  (every row, every column, every `\`-diagonal) must fully match.

## Your Task
Find the unique tile assignment that satisfies all line patterns. Read the
filled grid row by row, left to right, to recover the flag.

## Compliance
- Flag format: `zerosecure{...}`
- Zero unreasoned guessiness. The constraints admit exactly one solution.
