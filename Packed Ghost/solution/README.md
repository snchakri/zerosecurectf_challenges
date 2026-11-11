# Packed Ghost — solution

# PACKED GHOST

**Category:** Reverse Engineering · **Difficulty:** ★★☆ (40–60m)

> Something's packed in here. Unpack it. Or don't.


## Files
- `dist/challenge` — self-unpacking Linux x86-64 ELF

The binary carries an XOR-encrypted payload and decrypts it at runtime. Unpack
it the easy way (run it, dump the dropped file) or the hard way (reverse the
stub) — either way the payload hands you a flag. But the payload is a ghost.
What you want never made it into the payload at all; look at what the *stub*
says before it conjures anything.

Flag format: `DOOM{...}`


## Build
```
python build.py        # compiles payload + stub for Linux x86-64 in ctfbuild
```
Self-verifies: the packed binary runs, the earned-fake is only in the encrypted
payload (not in `strings`), and the egg lives in the stub.

> Needs the `ctfbuild` image (see `decoys/README.md`).

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
