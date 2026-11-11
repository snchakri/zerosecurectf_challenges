# Rust Enum State Machine

**Category:** Reverse Engineering

Deep inside Doctor Doom's citadel in Latveria, the inner vault is sealed by a
Doombot gate-warden. The warden does not check a password byte-for-byte; instead
it feeds every character you present through a small, cold-blooded automaton that
marches between internal postures -- *Init*, *HeaderVerified*, *PayloadScanned*,
*IntegrityChecked*, *Authorized* -- and the posture it is in decides how the next
character is mangled before being folded into a running seal. Only one sequence
of characters drives the automaton to settle its seal exactly onto the imprint
Doom etched into the lock. CICADA3301 has recovered the warden's logic core
(`dist/rev01_statemachine`). Reconstruct the automaton, reverse its folding, and
speak the phrase that opens the gate.

The accepted phrase is the flag.

**Download the attached file** (Linux x86-64 ELF) and recover the flag.
