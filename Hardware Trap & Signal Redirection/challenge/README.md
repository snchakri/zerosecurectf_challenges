# Hardware Trap & Signal Redirection

**Category:** Reverse Engineering

Doom does not hide his secrets in code you can read -- he hides them in the faults.
The relic CICADA3301 recovered (`dist/rev04_sigtrap`) walks a straight path that,
to any disassembler, seems to do nothing but crash: an illegal instruction here, a
division by zero there, a forbidden memory touch next. But each "crash" is caught
by a waiting handler that performs the real work on a hidden accumulator, nudges
the processor past the wound, and lets the march continue. The sequence of traps
is the program; the straight-line listing is a decoy. Follow the faults, model the
accumulator, and recover the phrase that makes the relic settle on Doom's seal.

The accepted phrase is the flag.

**Download the attached file** (Linux x86-64 ELF) and recover the flag.
