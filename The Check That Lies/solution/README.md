# The Check That Lies — solution

# THE CHECK THAT LIES

**Category:** Reverse Engineering · **Difficulty:** ★★☆ (30–50m)

> The vault keypad still works. Reverse it.


## Files
- `dist/challenge` — Linux x86-64 ELF, not stripped

`strings` will hand you a flag on a plate. Reversing the password check will
hand you another. Both are lies. There's a third thing in there that the
program will never print — because the branch that reaches it can't be taken.

Flag format: `DOOM{...}`


## Build
```
python build.py        # compiles for Linux x86-64 in the ctfbuild Docker image
```
The password is `concrete`. Build self-verifies bait/earned-fake/egg.

> Needs the `ctfbuild` image (see `decoys/README.md` for the one-time build).

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
