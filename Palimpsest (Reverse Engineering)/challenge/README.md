# Palimpsest

**Category:** Reverse Engineering

A vendor ships a "licensed" Python tool as compiled bytecode only (palimpsest.pyc, a marshalled CPython 3.13 code object). Recover the activation logic by disassembling the code object with stdlib marshal/dis, then run its invertible transform backwards to the one license key that unwraps the flag.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30059`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
