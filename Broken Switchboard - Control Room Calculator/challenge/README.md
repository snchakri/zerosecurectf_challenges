# Broken Switchboard - Control Room Calculator

Welcome to Broken Switchboard, where a humble calculator runs on dusty wiring, mysterious channels, and absolutely no quality assurance.

You are given a tiny four-function calculator.
Somewhere behind the panel is a hidden maintenance route.
Find a way to reroute execution and reach the admin path.

## Challenge Details
- Category: PWN / Function Pointer OOB
- Difficulty: Beginner-Intermediate
- Estimated Time: ~25 minutes
- Flag format: `ZeroSecure_CTF{...}`

## Runtime Note
- This challenge is self-contained.
- You do not need any external flag file, environment variable, or remote secret to solve locally.
- Only the provided binary is required for exploitation.

## Run
On Ubuntu/Linux:
1. `chmod +x ./switchboard`
2. `./switchboard`

## Hint Style
- Think beyond stack smashing.
- Observe global data layout and indirect calls.
- Menu channels are not always what they seem.

Good luck, operator. If the panel sparks, you are probably close.
