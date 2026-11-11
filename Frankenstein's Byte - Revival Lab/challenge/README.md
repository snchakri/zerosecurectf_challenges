# Frankenstein's Byte - Revival Lab

Welcome to a dusty revival lab where one tiny byte decides whether your creature sleeps forever or wakes up screaming.

The machine reads a name into a fixed chamber.
One extra byte can leak into the adjacent control gate.
Set the gate just right and the lab reveals the truth.

## Challenge Details
- Category: PWN / Off-by-One
- Difficulty: Beginner-Intermediate
- Estimated Time: ~20 minutes
- Flag format: `ZeroSecure_CTF{...}`

## Runtime Note
- This challenge is self-contained.
- You do not need any external flag file, environment variable, or remote secret to solve locally.
- Only the provided binary is required for exploitation.

## Run
On Ubuntu/Linux:
1. `chmod +x ./frankensteins_byte`
2. `./frankensteins_byte`

## Hint Style
- Byte order matters.
- Adjacent fields can be dangerous.
- Sometimes the 33rd byte is the only one that counts.

Good luck, doctor. Keep your sparks controlled.
