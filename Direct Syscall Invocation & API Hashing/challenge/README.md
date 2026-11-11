# Direct Syscall Invocation & API Hashing

**Category:** Reverse Engineering

Doom's field implants do not trust the operating systems they run on. The sentinel
CICADA3301 pulled off a captured Latverian relay (`dist/rev02_syscalls`) refuses to
call the kernel through the usual front doors -- it speaks to the machine with its
own bare `syscall` instructions, and it never names the routines it needs. Instead
it carries a ledger of numbers, the fingerprints of the API names it once resolved,
and from those fingerprints it spins a keystream that mangles whatever pass-phrase
you feed it. The relay unlocks only when the mangled stream lands on the imprint
Doom sealed inside. Recover the keystream from the fingerprints, invert the
mangling, and recover the phrase.

The accepted phrase is the flag.

**Download the attached file** (Linux x86-64 ELF) and recover the flag.
