# Cogwork

**Category:** Reverse Engineering

A vendor's license checker runs inside a tiny custom bytecode VM (the "Cog"). Recover the ISA from the stripped engine, disassemble the per-instance bytecode, and run its invertible gear-chain backwards to the one key that unlocks the flag. For the correct key the engine becomes a v2 "ratchet" generator that streams the flag one character per key-derived token; a wrong walk assembles a format-invalid decoy near-flag instead.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30054`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
