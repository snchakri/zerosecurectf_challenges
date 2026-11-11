# WebAssembly Linear Memory Validation

**Category:** Reverse Engineering

The outermost door of Doom's data-citadel does not run on the great machines
below -- it runs in a sandbox, a sealed little engine with a strip of memory and
a stack, so that even if an intruder reaches the console they find no password
to read, only a mechanism to understand. Lay your key into the engine's memory
and it feeds the bytes one at a time across its operand stack, each one bent by
a secret that shifts as the engine works, and sets the result beside a pattern
Doom pressed into the far end of that same memory. Lay down the one true key and
the door swings; lay down anything else and it simply says nothing and stays
shut.

CICADA3301 pried the engine's program loose as a single compiled module
(`dist/validator.wasm`) and rebuilt a bench harness to drive it
(`dist/run.js`). The module hides no plaintext key -- it carries only the folded
pattern and the rules that fold. Parse the module, read how the stack machine
walks linear memory and twists each byte by its running secret, and work the
mechanism backwards to the one key the gate accepts.

The accepted key is the flag.

**Download the attached files** and recover the flag.
