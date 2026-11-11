# Staged Hints: Hardware Trap & Signal Redirection

### Hint Level 1 (orientation)
The main loop looks inert because the work is not in the main loop. Each iteration
executes a two-byte faulting instruction and the registered signal handler does
the real transform, then advances RIP past the fault to resume. Set your debugger
to NOT swallow SIGILL/SIGFPE/SIGSEGV and watch what the handlers touch, or trace
the handler bodies statically.

### Hint Level 2 (reframe)
Three handlers, chosen by position `i % 3`: SIGILL (from `ud2`), SIGFPE (from
integer divide-by-zero), SIGSEGV (from a null read). Each applies a *different*
reversible byte operation and all three share one 32-bit accumulator that advances
every step. The per-byte key is derived from the accumulator (`k = (acc ^
(acc>>7)) & 0xFF`), and after each byte `acc = acc*1103515245 + 12345 + produced`.

### Hint Level 3 (strong nudge)
The accumulator advances using the *produced* byte, which is the target byte -- so
the whole schedule replays forward from the embedded seed and target. For each
position pick the handler by `i % 3` and invert it:
- `i%3==0` (SIGILL): `b = ((out - (acc & 7)) & 0xFF) ^ k`
- `i%3==1` (SIGFPE): `b = rotr8(out ^ k, 3)`
- `i%3==2` (SIGSEGV): `b = ((out ^ 0x6D) + k) & 0xFF`
then advance `acc`. No brute force.
