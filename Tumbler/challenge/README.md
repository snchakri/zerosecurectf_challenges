# Tumbler

**Category:** Cryptography

A sealed-token vault encrypts its secret unlock token with AES-128-CBC and will tell you only whether a submitted blob has valid PKCS#7 padding; use that one leaked bit (a classic CBC padding oracle) to recover the token and open it.

**Connect:** `nc <challenge-host> 30026`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
