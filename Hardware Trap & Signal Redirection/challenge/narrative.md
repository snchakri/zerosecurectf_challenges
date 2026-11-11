# Challenge: Hardware Trap & Signal Redirection (rev_04_signal_handler_control_flow)

**Category:** Reverse Engineering
**Difficulty:** Extreme
**Format:** `zerosecure{...}`

---

## Scenario & Objective

Doom does not hide his secrets in code you can read -- he hides them in the faults.
The relic CICADA3301 recovered (`dist/rev04_sigtrap`) walks a straight path that,
to any disassembler, seems to do nothing but crash: an illegal instruction here, a
division by zero there, a forbidden memory touch next. But each "crash" is caught
by a waiting handler that performs the real work on a hidden accumulator, nudges
the processor past the wound, and lets the march continue. The sequence of traps
is the program; the straight-line listing is a decoy. Follow the faults, model the
accumulator, and recover the phrase that makes the relic settle on Doom's seal.

The accepted phrase is the flag.

## Provided Files
- `dist/rev04_sigtrap` -- the fault-driven relic (stripped Linux x86-64 ELF, static).

## How to run
```
./rev04_sigtrap 'zerosecure{...}'      # or pipe the candidate on stdin
```
It prints an acceptance line and exits 0 for the correct phrase; otherwise
`rejected` and exit 1. (It deliberately raises and handles SIGILL/SIGFPE/SIGSEGV
internally -- this is expected, not a malfunction.)
