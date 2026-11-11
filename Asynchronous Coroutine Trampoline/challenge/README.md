# Asynchronous Coroutine Trampoline

**Category:** Reverse Engineering

Beneath the throne room of Castle Doom, a Latverian license daemon guards the
master key to the citadel's inner service grid. The infiltration cell of
CICADA3301 pulled one module from the daemon before the Doombots sealed the
vault: a cooperative scheduler that never runs a straight line of code. Instead
of ordinary functions, the gatekeeper hands control back and forth between a
handful of co-routines, each one surrendering and resuming mid-computation, the
real work smeared across a central dispatch loop.

Doom designed it this way on purpose. There is no single routine you can read
top to bottom; the transformation that turns a submitted key into the value the
daemon demands is spread across the hand-offs themselves, and each step quietly
poisons the next with a running state that nobody writes down.

Your objective: recover the one key string the gatekeeper will accept. The
daemon confirms a correct key and rejects everything else, but it will not tell
you *why* — you must reconstruct its logic and walk it backwards.

**Download the attached file** (CPython 3.13 bytecode) and recover the flag.
