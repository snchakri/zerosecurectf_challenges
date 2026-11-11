# Lacquerbox

**Category:** Reverse Engineering

A vendor's license sealer runs a home-grown balanced Feistel block cipher (the "Lacquer") over your token. Recognise the Feistel structure from the stripped engine, recover its SHA-256 key schedule, and run the round-network backwards from the embedded target to the one token that unwraps the flag.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30057`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
