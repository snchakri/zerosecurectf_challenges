# Carillon

**Category:** Reverse Engineering

A vendor's license checker runs inside a custom REGISTER bytecode VM whose program is ENCRYPTED on disk and only decrypts per-instruction at fetch time. The dispatch loop is control-flow-FLATTENED with opaque predicates and decoys, and the key check is not a compare but a keyed GF(2^8) substitution-permutation network. Recover the ISA, decrypt + lift the flattened bytecode, model the SPN the VM computes, and invert it (field linear algebra + inverse S-box) to the one key that unwraps the flag.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30053`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
