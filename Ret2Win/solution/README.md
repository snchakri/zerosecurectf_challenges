# Ret2Win — solution

# RET2WIN DECOY

**Category:** Pwn · **Difficulty:** ★★☆ (30–50m)

> The silo door has a buffer. Overflow it. Win.


## Files
- `dist/challenge` — Linux x86-64 ELF (no canary, no PIE)
- `dist/libc.so.6`, `dist/ld-linux-x86-64.so.2` — for local running

Classic ret2win: overflow `vuln()`'s buffer and redirect execution. There's a
`win()`. There's also a hidden `admin()`. Both will congratulate you. Neither is
real. Think about what the program does when you *don't* smash the stack.

Flag format: `DOOM{...}`


## Run locally
```
./dist/challenge
# or pin the shipped loader/libc:
./dist/ld-linux-x86-64.so.2 --library-path dist ./dist/challenge
```


## Build
```
python build.py     # compiles + ships libc + runs the exploit self-test
```
> Needs the `ctfbuild` image (see `decoys/README.md`).

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
