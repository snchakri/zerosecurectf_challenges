# Ferrule

**Category:** Reverse Engineering

A tiny firmware-activation crackme seals its flag under a short repeating-key XOR and confirms the key with an FNV-1a checksum, so nothing useful survives `strings`. Read the one-line decode loop, apply the known flag-format prefix as a crib, and the key (and flag) fall out by known-plaintext XOR.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30055`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
