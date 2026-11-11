# Format String Illusion

## Story
An incident-response export from a backend cluster looks like routine failure logs.
A teammate insists the attacker hid data in the formatting itself, not the literal words.

## Your Task
Inspect `challenge.txt` and recover the hidden flag.
The payload is disguised as noisy server logs, but the capitalization pattern of letters carries the real ciphertext.

## Rules
- Keep only alphabetic characters (`A-Z` and `a-z`) in their original order.
- Use case as a two-state signal.
- Split the signal into groups of 5 and decode with a Baconian mapping.
- Submit only the final flag.
- Flag format is: `ZeroSecure_CTF{...}`
- Keep exact characters (case-sensitive).

Good luck.