# Branchless AVX2 SIMD Vectorization

**Category:** Reverse Engineering

Doom does not tolerate hesitation, not even in his locks. The passcode gate on
the citadel's fabrication floor was cut to run in perfect lockstep: it swallows
your key thirty-two letters at a time and grinds every lane of it in parallel,
never pausing, never branching, never leaking a single clock of difference
between a right guess and a wrong one. Doombot engineers are proud of it -- they
say the gate reveals nothing by how long it thinks, because it always thinks
exactly the same. Each letter is pushed through a little hall of mirrors (two
lookup slabs that rewrite its halves), nudged and flipped by a fixed per-slot
pattern, and then, per lane, one of two parallel grindings is chosen by a mask
etched into the die. At the end the gate slaps the whole result against an
imprint and opens only on a flawless match.

CICADA3301 pulled the gate's logic core off the floor controller
(`dist/rev09_checker`, a stripped Linux x86-64 binary) during a maintenance
window. The lookup slabs, the nudge-and-flip pattern, the lane mask and the
imprint are all still in there. Because the grinding treats each slot the same
way no matter what letter sits in it, every mirror can be walked backwards.
Recover the one key the gate will accept.

The accepted key is the flag.

**Download the attached file** and recover the flag.
