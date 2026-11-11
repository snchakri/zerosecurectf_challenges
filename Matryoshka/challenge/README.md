# Matryoshka

**Category:** Cryptography

An intercepted message wrapped in nested, self-identifying encoding layers (hex over base64 over base32) around an Atbash+Caesar core. Recognise each layer by its alphabet, peel from the outside in, then undo Atbash and brute the 25 Caesar shifts to reveal the flag.

**Connect:** `nc <challenge-host> 30019`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
