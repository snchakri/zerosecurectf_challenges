# Mixed Boolean-Arithmetic

**Category:** Reverse Engineering

Doom's cryptographers do not write a clean equation where a spy might read it.
The lock CICADA3301 pried from the citadel's archive (`dist/rev05_mba`) checks
your key through a thicket of ANDs, ORs, XORs, NOTs and shifts tangled with
additions and multiplications -- a deliberate briar of Mixed Boolean-Arithmetic.
Beneath the thorns, each character obeys a simple rule, and the characters are
chained so that each leans on the one before it. Cut through the briar, collapse
the identities back to the plain equation, unwind the chain, and the key falls
out.

The accepted key is the flag.

**Download the attached file** (Linux x86-64 ELF) and recover the flag.
