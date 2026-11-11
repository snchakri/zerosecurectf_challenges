# Cat The Wrong Flag — solution

# CAT THE WRONG FLAG

**Category:** Pwn · **Difficulty:** ★★★ (45–70m)

> The retrieval terminal will fetch any file you name. There's just nothing
> worth fetching — the vault is sealed in software.


## Files
- `dist/challenge` — Linux x86-64 ELF (no canary, no PIE)
- `dist/libc.so.6`, `dist/ld-linux-x86-64.so.2` — for local running

There's no flag on disk and nothing in `strings`. The flag is encrypted inside
the binary and only `open_vault()` turns it back into text — and `main()` never
calls `open_vault()`. Overflow the read buffer in `vuln()` and redirect the
saved return address into `open_vault()` yourself. A `pop rdi; ret` / `ret`
gadget is provided for stack alignment.

Flag format: `ZeroSecure{...}`


## Run locally
```
cd dist && ./ld-linux-x86-64.so.2 --library-path . ./challenge
```


## Build
```
python build.py     # compiles + ships libc + runs the exploit self-test
```
> Needs the `ctfbuild` image (see `decoys/README.md`).

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
