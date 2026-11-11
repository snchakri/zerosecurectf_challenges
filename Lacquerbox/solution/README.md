# Lacquerbox — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --image challenge/challenge.lacq --bin challenge/lacq
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Lacquerbox — Official Write-up

**Category:** rev · **Band:** Hard · **Flag:** `zerosecurectf{...}` (per-instance flag text is the same string for every team; only the *token* and *image* differ)

---


## 1. What the player is given

- `lacq` — a small, stripped x86-64 ELF. Identical for every team.
- `challenge.lacq` — a per-team binary image (≈350 bytes).

Running the engine on any token prints `DENIED …` unless the token is the one
the vendor would have issued. `strings challenge.lacq` and `strings lacq` reveal
nothing resembling the flag.


## 2. Reversing the engine

The engine does five things, in order:

1. **Loads the image.** Header is `"LACQ" | u8 ver | u8 L | u8 R | u8 seed_len |
   u16 flag_len`, followed by `sbox[256]`, `master[seed_len]`, `expected[L]`,
   `flag_ct[flag_len]`. All little-endian. `L` is the block/token length (even),
   `R` the round count.

2. **Reads a token** from stdin and requires `len == L`.

3. **Seals the token** with a transform (details below) and compares the result
   to `expected[L]`.

4. **Derives a keystream from the token** — `SHA256(token‖0) ‖ SHA256(token‖1) ‖
   …` truncated to `flag_len` — and XORs it with `flag_ct` to recover the flag.

5. Prints the flag **iff** the comparison in step 3 passed; otherwise `DENIED`.

The crucial observation for step 4/5: **the keystream is derived from the token,
not from the cipher output or from any image field.** So even if you patch the
`memcmp`/branch in step 5 to always print, the engine still XORs `flag_ct` with
`keystream(your_wrong_token)` and emits garbage. The flag is *bound to the
correct token*. Patching and `strings` are both dead ends — you must find the
token.

### 2.1 The transform is a balanced Feistel network

Reading `encrypt()` (the handler names are stripped; recover it from the
structure), the block of `L` bytes is processed as:

```
b ^= wk1                                  # pre-whitening (L bytes)
for r in 0 .. R-1:
    Lh, Rh = b[:h], b[h:]                 # h = L/2
    b = Rh  ||  (Lh XOR F(Rh, rk[r]))     # Feistel round + swap
b ^= wk2                                  # post-whitening (L bytes)
```

This is the textbook **balanced Feistel** round: the left half is replaced by
the right half, and the right half becomes the old left half XORed with a
function of the old right half. (Same shape as DES, GOST 28147-89, Blowfish.)

The round function is:

```
F(x[0..h-1], rk[0..h-1]):
    t[i] = sbox[(x[i] + rk[i]) & 0xff]        # key add + S-box substitution
    t[i] = rol8(t[i], x[(i+1) mod h] & 7)     # data-dependent rotation (RC5-ish)
    for i in 1..h-1: t[i] ^= t[i-1]           # intra-half diffusion chain
```

### 2.2 The key schedule

`wk1`, `wk2` and every round subkey `rk[r]` are **not** stored in the image.
They are derived from the 16-byte `master` seed by a SHA-256 KDF:

```
kdf(master, tag, idx, n) = ( SHA256(master‖tag‖idx‖0)
                           ‖ SHA256(master‖tag‖idx‖1) ‖ … )[:n]

rk[r] = kdf(master, "RK", r, h)       for r = 0..R-1
wk1   = kdf(master, "WK", 1, L)
wk2   = kdf(master, "WK", 2, L)
```

So from `master` (which *is* in the image) and the fixed tags/indices, the whole
key schedule is reproducible. The S-box is read directly from the image.


## 3. The crux — invert the network, don't invert F

The decisive insight is the defining property of a Feistel network: **a round is
invertible even though its round function `F` is not.** You never have to undo
`F` (which mixes an S-box, a data-dependent rotation and a chain, and is not a
bijection). Given a round's output `(Lh', Rh')`:

```
forward:   Lh' = Rh            Rh' = Lh XOR F(Rh)
=>         Rh  = Lh'           Lh  = Rh' XOR F(Lh')   (since Rh = Lh')
```

Because every layer — the two whitening XORs and each Feistel round — is a
bijection on the L-byte block, `expected` has exactly **one** preimage. There is
no search and no guesswork: the token is uniquely determined.

### 3.1 Decryption procedure

```
b = expected XOR wk2                      # peel post-whitening
for r in R-1 .. 0:                        # reverse round order
    newLh, newRh = b[:h], b[h:]
    Rh = newLh                            # new left was old right
    Lh = newRh XOR F(Rh, rk[r])           # recompute F on the known Rh
    b = Lh || Rh
token = b XOR wk1                         # peel pre-whitening
```

Feed `token` to the engine → it seals to `expected`, derives the matching
keystream, and prints the flag.


## 4. Reference solver

`solution/solve.py` implements exactly this: it parses the image, rebuilds the key
schedule with the recovered SHA-256 KDF, runs the network backwards, verifies
`encrypt(token) == expected`, and (with `--bin`) runs the real engine to print
the flag. It performs **no search** — a single deterministic inversion.

```
$ python3 solution/solve.py --image challenge.lacq --bin ./lacq
[+] recovered license token: LsKQGV6ME788DTJOz2
[+] engine response: zerosecurectf{...}
[+] FLAG = zerosecurectf{...}
```


## 5. Honest difficulty band

**Band: Hard — honestly stated, with the caveat that it sits at the Medium-Hard
border for a player fluent in symmetric-cipher structure.**

What makes it Hard:
- You must *recognise* the construction as a Feistel network from stripped,
  optimised code — the handler names, the half-split and the swap are not
  labelled. Misreading it as an invertible stream of per-byte ops (as in a VM
  crackme) sends you down a blind alley trying to invert `F`.
- You must reconstruct a **SHA-256 key schedule** (round subkeys + two whitening
  keys from a master seed) — not just read constants out of the image.
- The round function deliberately layers confusion (S-box), key mixing,
  **data-dependent rotation** (RC5/TEA-flavoured) and intra-half diffusion, so a
  casual "it's just XOR" read fails.
- The flag wrap means the usual CTF shortcuts (`strings`, NOP the compare, flip
  the jump) are provably useless; see §6.

What keeps it from Extreme / caps it at Hard:
- Once the Feistel shape is seen, the inversion is mechanical and well known; a
  cryptographer solves it quickly.
- It is a single stage (no chaining), the block is small, and the key schedule,
  while nonlinear, is fully present in the image.

This matches the recorded axes in `challenge.yml` (depth 4, guess 1, search 1,
novelty 3). We do **not** inflate it to Extreme.


## 6. Red-team / adversarial analysis (honest)

We tried the standard ways to cheat the challenge; the acceptance test

- **`strings` / grep for the flag.** Fails: the flag is never in the image or
  the binary in the clear (`flag absent from image`, `flag absent from engine
  binary`). It is `flag_ct = flag XOR keystream(token)`.
- **Patch the comparison to always print.** Fails *by construction*: the
  keystream is `SHA256(token‖·)` of the *submitted* token, so a patched engine
  with a wrong token XORs `flag_ct` with the wrong keystream and prints garbage
  (`wrong token unwraps to garbage (patch useless)`). Recovering the flag is
  equivalent to recovering the token — there is no shortcut around the math.
- **Brute force the token.** Infeasible: `L` is 14–18 printable bytes
  (≥ 62¹⁴ ≈ 10²⁵ candidates); the design has no small-space fallback.
- **Guess from structure / "tell" leakage.** Guessiness is 1: the preimage is
  unique and reasoning-recoverable; nothing requires a lucky guess.
- **Cross-instance replay.** Fails: S-box, master seed, `L`, `R`, target and
  token all vary per seed (`different seed -> different target / token`), and the
  same seed is byte-identical (`determinism`), so one team's solution does not
  transfer.
- **Dodge the length check.** Wrong-length and single-bit-flipped tokens are
  both DENIED with no flag (`wrong-length token is rejected`, `wrong token is
  DENIED`).

### AI-resistance (honest)

- **Where an LLM helps:** recognising a Feistel structure and the "don't invert
  F" trick is well represented in training data; a capable model will likely
  name the construction and sketch the inversion. This is *not* a strong
  AI-resistance challenge, and we do not claim it is.
- **Where it still bites:** the model must read the *specific* stripped layout
  correctly — the exact whitening placement, the round-order of the key
  schedule, the `(i+1) mod h` index of the data-dependent rotation, and the
  intra-half chain direction. Getting any of these backwards yields a wrong
  token and no flag, and there is no oracle other than `encrypt(token) ==
  expected`, so a hallucinated-but-plausible inversion is caught immediately.
  The per-instance master/S-box mean a model cannot regurgitate a memorised
  answer.
- **Net:** a reasoning aid, not a wall. Honest classification: **R** (realistic),
  medium AI-resistance. For AI-hard events pair it (via `CHAIN`) with a stage
  whose inputs come only from a memory capture, or move the crux deeper
  (`CONCEAL-SHIFT`) behind control-flow obfuscation as in the sibling `oxbow`.


## 7. Lineage

- **Source corpus (adapted, not copied):**
  `snchakri/zerosecurectf2026_challenges : reverse_eng/ch2_matryoshka_protocol`.
  The source is a C crackme that "always rejects your token; recover the flag by
  reversing and patching the control flow" — a nested-encapsulation ("matryoshka")
  motif whose flag is stored as plaintext bytes in a `print_flag()` function and
  is obtained by flipping a single conditional-jump byte (`je`↔`jne`). We kept
  only the *idea* — peel nested layers to recover a secret — and rebuilt it:
  - `GROUND`: the abstract "nesting" becomes a genuine **balanced Feistel
    network** (the canonical nested-round cipher family — DES, GOST, Blowfish),
    giving a real-world crux instead of a toy.
  - `GUARD-SWAP`: the artificial, patch-defeatable plaintext flag is replaced by
    a **SHA-256 keystream wrap bound to the correct token**, so `strings` and
    binary patching are provably useless (CWE-656 security-through-obscurity →
    real key-bound mitigation).
- **Corpus genome seed** (`corpus-genome.yaml`): `zsctf-rev-018` *Flare
  Authenticator* — "software licensing / keygen; per-instance key material"
  (`SUBSTITUTE-TARGET`: obfuscated Qt crackme → stripped native block-cipher
  sealer).
- **Operators** (`system.html` §17.3): `GROUND` → `GUARD-SWAP` →
  `SUBSTITUTE-TARGET` (the documented authenticity-raising composition).
- **Distinct from our existing rev set:** cogwork (custom bytecode VM / per-byte
  independent bijections), oxbow (control-flow-flattened dispatch loop),
  keywright (linear-system keygen) and palimpsest (Python bytecode). Lacquerbox
  is the only one built on a *symmetric block cipher with inter-byte Feistel
  mixing and a derived key schedule*.

---

*Self-contained educational crackme. The only "exploit" is understanding the
program's own cipher; it targets no real system and carries nothing
weaponizable.*
