# Simple User Pass — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Inspect the binary in a disassembler or run `strings challenge/userpass`.
2. Locate the username/password comparison and recover the accepted credentials.
3. Run the binary and supply those credentials. The original writeup gives the exact values and successful interaction.

Author procedures and reference material:

- [Simple_User_Pass_README.md](Simple_User_Pass_README.md)
- [overviewuserpass.md](overviewuserpass.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

1. Compute the position-weighted sum of username `binary`: 2322.
2. XOR with `3 * ord("b")`: 2100.
3. Shift left by the actual `argv[0]` length. The wrapper deliberately invokes `./userpass` (10 characters), so the password is 2150400.
4. Run `./userpass binary 2150400` from the player directory. The wrapper reproduces that exact invocation.

```bash
python solution/solve.py
```
