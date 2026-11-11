# Thermal Boundary — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Unpack the participant package and read the VM instruction contract.
2. Send bytecode that triggers the secret-dependent probe-table access.
3. Measure cache-hit timing per probe index to recover one byte at a time.
4. Repeat for the flag length and combine the recovered bytes. The complete bytecode and solver procedure are in `author/thermal_boundary_complete_writeup.md`.

Author procedures and reference material:

- [author/thermal_boundary_complete_writeup.md](author/thermal_boundary_complete_writeup.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.
