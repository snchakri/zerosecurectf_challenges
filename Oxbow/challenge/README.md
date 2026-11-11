# Oxbow

**Category:** Reverse Engineering

A vendor's license checker is a control-flow-FLATTENED dispatch loop over a shuffled table of blocks. Recover the engine, resolve the opaque predicates that pick each block's live successor, reconstruct the real pipeline (ignoring the decoy "oxbow" branches), and invert it to the one key that unwraps the flag.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30058`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
