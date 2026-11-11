# Challenge: Rule 30 Lattice Warden (rev_07_cellular_automata_rule30)

**Category:** Reverse Engineering
**Difficulty:** Hard
**Format:** `zerosecure{...}`

---

## Scenario & Objective

High in the north spires of Castle Doom, past the brass orrery that never stops
turning, a lattice warden keeps the schematics for the citadel's weather engine.
It is not a lock of tumblers and teeth. The warden takes whatever key you offer,
burns its bits into the first row of a long iron loom, and lets Doom's favourite
automaton weave the row forward generation by generation -- each thread choosing
its next colour only from the neighbour on its left and the pair at its centre
and right. After a hundred-odd passes the loom stops, and the warden lays the
finished cloth against the sigil its maker pressed into the frame. Match the
sigil and the spire opens; miss by a single thread and the loom resets in
silence.

A CICADA3301 forward team lifted the warden module (`dist/checker.pyc`) during
the long dark of the citadel's power cycling. Doom believed the weave ran one
way only. The team suspects the loom keeps a thin logbook along one edge, and
wonders whether the finished cloth and that edge together are enough to pull
every thread back to where it began. Recover the seed row the warden accepts.

The accepted key is the flag.

## Provided Files
- `dist/checker.pyc` -- the extracted lattice warden (CPython 3.13). Feed a
  candidate key on standard input.

## How to run
```
printf '%s' 'zerosecure{...}' | python dist/checker.pyc
```
It prints an acceptance line and exits 0 for the correct key; otherwise
`ACCESS DENIED.` and exit 1.
