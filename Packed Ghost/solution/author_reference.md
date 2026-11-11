<a id="c107"></a>
## 107 · Packed Ghost

**Chamber:** Reverse Engineering · **Band:** broken set · **Status:** decoy honeypot (unsolvable by design; DOOM{...} submissions = signal)  
**Flag:** `(hidden random)`

### PACKED GHOST

**Category:** Reverse Engineering · **Difficulty:** ★★☆ (40–60m)

> Something's packed in here. Unpack it. Or don't.

#### Files
- `dist/challenge` — self-unpacking Linux x86-64 ELF

The binary carries an XOR-encrypted payload and decrypts it at runtime. Unpack
it the easy way (run it, dump the dropped file) or the hard way (reverse the
stub) — either way the payload hands you a flag. But the payload is a ghost.
What you want never made it into the payload at all; look at what the *stub*
says before it conjures anything.

Flag format: `DOOM{...}`

#### Build
```
python build.py        # compiles payload + stub for Linux x86-64 in ctfbuild
```
Self-verifies: the packed binary runs, the earned-fake is only in the encrypted
payload (not in `strings`), and the egg lives in the stub.

> Needs the `ctfbuild` image (see `decoys/README.md`).


