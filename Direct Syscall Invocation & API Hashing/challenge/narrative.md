# Challenge: Direct Syscall Invocation & API Hashing (rev_02_dynamic_anti_hooking_syscalls)

**Category:** Reverse Engineering
**Difficulty:** Extreme
**Format:** `zerosecure{...}`

---

## Scenario & Objective

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

## Provided Files
- `dist/rev02_syscalls` -- the captured relay (stripped Linux x86-64 ELF, static; emits via direct syscalls).

## How to run
```
./rev02_syscalls 'zerosecure{...}'      # or pipe the candidate on stdin
```
It prints an acceptance line and exits 0 for the correct phrase; otherwise
`rejected` and exit 1.
