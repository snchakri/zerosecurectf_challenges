# Echo Chamber - Legacy Console

A dusty terminal insists it only repeats what you say, yet a hidden control gate hums behind every echo.

The system exposes a legacy formatter and a single admin gate.
Set the gate value exactly right to unlock the real output.

## Challenge Details
- Category: PWN / Format String
- Difficulty: Beginner-Intermediate
- Estimated Time: ~20 minutes
- Flag format: `ZeroSecure_CTF{...}`

## Runtime Note
- This challenge is self-contained.
- You do not need any external flag file, environment variable, or remote secret to solve locally.
- Only the provided binary is required for exploitation.

## Run
On Ubuntu/Linux:
1. `chmod +x ./echo_chamber`
2. `./echo_chamber`

## Hint Style
- Observe startup hints carefully.
- Not every flag-like string is real.
- The admin gate accepts only one exact value.

Good luck. In this chamber, even silence can be loud.
