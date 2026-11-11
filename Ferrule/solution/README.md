# Ferrule — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local challenge/ferrule
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Ferrule — official writeup

**Flag:** `zerosecurectf{f3rrul3_crimps_th3_fl4g_under_a_r3p34ting_x0r}` (static
demo seed; per-instance in production)

**Band:** Easy (honest). This is a deliberate beginner on-ramp: one short decode
loop, one well-known crib, no tooling beyond `objdump`/a hex view and a few
lines of Python.


## What the binary does

Reading `challenge/src/ferrule.c` (or the `-O0` disassembly) shows the whole
check in one function:

```c
for (i = 0; i < SECRET_LEN; i++)
    out[i] = SECRET[i] ^ key[i % klen];      /* repeating-key XOR */
if (fnv1a32(out, SECRET_LEN) == EXPECT_HASH) /* confirm the key   */
    print(out);                              /* out == the flag   */
```

So:

* `SECRET[]` is an embedded byte array — the flag sealed under a short
  **repeating-key XOR**.
* The program never stores the key or the flag's format string. It confirms a
  candidate key by decoding `SECRET` and checking a 32-bit **FNV-1a** checksum
  (`EXPECT_HASH`). That is why `strings` yields nothing: there is no plaintext
  flag, no plaintext key, not even the `zerosecurectf{` prefix in the image.


## Why it is solvable (the crib)

The decoded payload *must* be the flag, and every ZSCTF flag starts with the
known 14-byte prefix `zerosecurectf{`. XOR is its own inverse, so for the first
14 bytes of `SECRET`:

```
key[i % klen] = SECRET[i] XOR "zerosecurectf{"[i]        (i = 0 .. 13)
```

The recovered bytes **repeat** with the key's period, which both reveals the key
length (7 here) and cross-checks the recovery. With the full key in hand, XOR
the whole `SECRET` array to get the flag — no need to run the binary at all.


## Steps

1. Find `SECRET[]`. By hand: `objdump -s -j .rodata ferrule` (or follow the
   array's symbol with `nm`/`readelf -s`, since the build keeps its symbol
   table). The reference solver instead scans the whole file for the one offset
   where the crib yields a consistent short repeating key — so it works even on
   a stripped binary.
2. `key = SECRET[:14] XOR "zerosecurectf{"`, then collapse to its period (7).
3. `flag = SECRET XOR repeat(key)`.
4. (Optional) feed the 7-character key to the running unit (`./ferrule`, or
   `nc host 1337`) to watch it unlock.

```bash
python3 solution/solve.py --local build/ferrule
# [*] recovered activation key = 'XXXXXXX' (len 7)
# [*] decoded flag offline     = zerosecurectf{...}
# [+] FLAG = zerosecurectf{...}
```


## Integrity / why the cheap shortcuts do not work

* **`strings` fails by construction.** The flag, the key, and the format prefix
  are all absent in plaintext — only `SECRET` (flag XOR key) and a 4-byte
  string exists in the binary.
* **Guessing the key fails.** The 7-byte key is derived from a SHA-256 of the
  per-team seed over a 32-symbol alphabet (~2^34 keys); a wrong key is declined
  by the checksum. The test checks a wrong key and a one-byte-off near miss are
  both declined.
* **The intended path needs no brute force.** The crib collapses the problem to
  a handful of XORs.


## Design notes (for the ZSCTF team)

* **Lineage (reconstruction, system.html §17 / corpus-genome.yaml):** the
  repeating-key-XOR keygen is the archetypal beginner crackme transform; this
  instance pairs it with a checksum self-check (so no plaintext crib is stored)
  and a known-format crib (so it is cleanly solvable). Sibling easy-rev on-ramps
  in the corpus (`cogwork`, `keywright`) teach control-flow and symbol reading;
  Ferrule isolates the single idea of *known-plaintext recovery*.
* **Per-instance:** `ZSCTF_SEED` → activation key (so keys differ per team);
  `ZSCTF_FLAG` → sealed `SECRET` + `EXPECT_HASH`. Same seed+flag ⇒ byte-identical
  binary; different seed ⇒ different key and different binary (both asserted).
* **Harder variants (extrapolation, not shipped):** multi-byte key schedule
  driven by an LCG; moving the XOR constant into a decode routine resolved only
  at runtime; or stripping + light control-flow flattening (that is the `oxbow`
  neighbourhood and raises the band well past Easy).
