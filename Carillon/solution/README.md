# Carillon — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --image challenge/challenge.car --bin challenge/carillon
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Carillon — official writeup

**Category:** rev · **Band:** Extreme (honest; see §9) · **Flag:** `zerosecurectf{...}`

Carillon is a register-based bytecode **virtual machine** that validates a
license key. It is deliberately harder than the sibling rev challenges: the
bytecode is **encrypted** and only decrypts at fetch time, the control flow is
**flattened** with **opaque predicates**, and the key check is **a system you
must model and solve** (a small keyed permutation over GF(2⁸)) — not a per-byte
compare and not an op-by-op-invertible pipeline.

This document is the organiser reference: it specifies the ISA exactly, walks
the intended solve, states the band honestly, discloses the dynamic shortcut,
and records the unintended-path scan.

---


## 1. What you are looking at

A player receives the stripped engine `carillon` and a per-instance image
`challenge.car`. The engine's shape is:

```c
state = ENTRY;
while (steps++ < CAP) {
    rec = DECRYPT(image.blocks[state]);   // 10 bytes, XOR SHA-256 keystream
    execute_one_instruction(rec);         // over the register file
    if (rec.op == HALT) break;
    state = pred(rec.pk, rec.c) ? rec.sA : rec.sB;
    if (state >= nblk) break;
}
accept iff REG[0..L-1] == expected[0..L-1];
```

Three layers of hardening stack here:

- **Encrypted bytecode.** `objdump`/`strings` on the image show only
  ciphertext. Each block `i` is stored XORed with `SHA256(bkey ‖ u32le(i))[:10]`
  and is decrypted only when the dispatcher fetches it.
- **Control-flow flattening.** There is no readable instruction sequence —
  only a shuffled table of blocks and a loop that jumps by computed next-state.
- **Opaque predicates + decoys.** The next state is `pred(pk,c) ? sA : sB`
  where `pred` is a parity tautology the compiler cannot fold; the dead edge
  points at decoy blocks that never run on the live path.

---


## 2. The engine (recovered) — the ISA spec

### Image format (little-endian)

```
offset  size  field
0       4     magic "CARL"
4       1     version (1)
5       1     L            key length / state width (22, 24, or 26)
6       1     R            number of rounds (2 or 3)
7       1     nreg         register-file size (64)
8       2     flag_len
10      2     nblk         number of blocks in the table
12      2     entry        starting block index
14      2     reserved (0)
16      16    bkey         per-instance bytecode-decryption key
32      256   sbox[256]    byte-substitution table (a permutation of 0..255)
288     10*nblk  blocks    ENCRYPTED block table (see below)
...     L     expected[L]  the comparison target
...     1     NL           number of nested flag-peel layers
...     ...   peel[NL]     per layer: decoy lane then real lane, each
                           (u16 plen | u8 tag[4] | u8 ct[plen]); see §12
```

### Block record (10 bytes, after decryption)

```
op, d, a, imm, sA_lo, sA_hi, sB_lo, sB_hi, pk, c
```

`sA`/`sB` are u16 successor indices. Decryption of block `i`:

```
plain[k] = cipher[k] XOR SHA256(bkey ‖ u32le(i))[k]    for k in 0..9
```

### Register-VM opcodes

The register file `REG[nreg]` holds bytes (GF(2⁸) elements). The license key is
loaded into `REG[0..L-1]` at start; the rest are zero.

| op   | mnemonic | effect |
|------|----------|--------|
| 0x00 | `HALT`   | stop the dispatcher |
| 0x1A | `CLR d`  | `REG[d] = 0` |
| 0x2B | `MOV d,a`| `REG[d] = REG[a]` |
| 0x3C | `XORI d,imm` | `REG[d] ^= imm` |
| 0x4D | `GFMULI d,imm` | `REG[d] = gfmul(REG[d], imm)` |
| 0x5E | `GFMAC d,a,imm` | `REG[d] ^= gfmul(REG[a], imm)` |
| 0x6F | `SBOXR d` | `REG[d] = sbox[REG[d]]` |

`gfmul` is multiplication in **GF(2⁸) with the AES reduction polynomial
`0x11B`** (`x⁸+x⁴+x³+x+1`).

### The edge selector — the flattening

```c
int pred(uint8_t pk, uint8_t c){
  uint32_t x = c;
  switch (pk & 3){
    case 0: return (x*x - x) & 1;         // always 0  (x(x-1) is even)
    case 1: return (x*x + x) & 1;         // always 0  (x(x+1) is even)
    case 2: return ((x*x - x) & 1) ^ 1;   // always 1
    default:return (x*x + x + 1) & 1;     // always 1  (even + 1)
  }
}
```

`x(x±1)` is a product of consecutive integers, hence even, so `pred` is a
**constant** fixed by `pk` — a tautology the optimiser leaves in place. It is a
function of the image byte `c` only: **the control flow is key-independent**
(this is the deliberate shortcut; see §9).

---


## 3. What the VM computes — the keyed permutation

Lifting the live path yields a long straight-line program that, grouped, is:

```
state = key                                  # REG[0..L-1]
for r in 0..R-1:
    state = A_r · state (+) c_r               # full GF(2^8) matrix mul + const
    state = SBOX[state]                        # bytewise substitution
expected = state
```

The affine layer `A_r · state (+) c_r` is emitted as:

- `CLR` the scratch registers `REG[L..2L-1]`,
- for each output `i` and input `j` with `A_r[i][j] ≠ 0`, a
  `GFMAC (L+i), j, A_r[i][j]` (i.e. `scratch[i] ^= A_r[i][j]·state[j]`),
- an `XORI (L+i), c_r[i]` to add the constant,
- `MOV i, (L+i)` to copy the scratch back to the state,

then the S-box layer is `SBOXR 0 … SBOXR (L-1)`. Within a round, the MAC/const
instructions are **shuffled** (XOR is commutative, so this is sound) to blunt
pattern-matching.

Each `A_r` is a random **invertible** `L×L` matrix over GF(2⁸); `SBOX` is a
random byte permutation. This is a miniature substitution–permutation network:
every output byte depends on every input byte. **There is no per-byte structure
to attack and no way to run it backwards one instruction at a time** — the
matrix multiply destroys per-instruction invertibility (`CLR` then accumulate).

---


## 4. The intended solve

1. **Recover the ISA** (§2) from the stripped engine: dispatcher, 10-byte
   record, the seven opcodes, `gfmul`'s `0x11B`, the per-block SHA-256
   decryption, and `pred`.
2. **Parse + decrypt + lift.** Decrypt each fetched block; from `entry`, follow
   the live edge `pred(pk,c) ? sA : sB` to `HALT`, collecting instructions.
   Decoys (dead-edge-only blocks) never appear on the live path.
3. **Segment at the S-box layers.** A full S-box layer is `L` consecutive
   `SBOXR` on regs `0..L-1`. Splitting on these yields `R` linear sections.
4. **Recover each affine map symbolically.** Execute a linear section with the
   `L` state registers initialised to the unit affine forms
   `e_0 … e_{L-1}` over GF(2⁸); the resulting state registers spell out the
   matrix rows `A_r[i][·]` and constant `c_r[i]`. (This is the step that makes
   it *modelling a system*: you assemble the matrix, you do not invert op by op.)
5. **Invert the system.** Peel the rounds from `expected` backwards: undo the
   S-box with `SBOX⁻¹`, then solve `A_r · in = out ⊕ c_r` for `in` via a
   GF(2⁸) **matrix inverse** (hand-rolled Gauss–Jordan). After `R` rounds you
   have the unique key `X`.
6. **Win.** Feed `X` to the engine; it recomputes the keystream from `X`,
   unwraps `flag_ct`, and prints the flag.

The reference solver [`solution/solve.py`](solution/solve.py) does all of this with
**Python 3 stdlib only** — no z3, no pwntools, no sage. It hand-rolls GF(2⁸)
(log/exp tables), Gauss–Jordan inversion, and the symbolic affine executor.

Measured end-to-end on the acceptance instance (`L=26, R=3, ~2330 live
instructions, ~4660 blocks`): **lift + model + invert in ≈ 0.16 s.**

---


## 5. The flag is extracted by a nested peel — not one XOR

Recovering the key `X` is **not** the flag; it is the *means* to extract it. The
flag is never a one-shot XOR of the key. It is split into `NL` ordered fragments
hidden in `NL` **nested** layers (full detail in **§12 Flag extraction**). Only
`X` opens layer 0; each layer yields one fragment **plus** the seed that opens
the next; a wrong peel (or stopping early) is rejectable by the published flag
format. So:

- `strings`/`grep` on the binary or the image find nothing — every layer is
  ciphertext, and the only embedded `zerosecurectf{…}` literal anywhere is the
  clearly-marked `REPLACE_ME_AT_DEPLOY` placeholder (the env-unset fallback),
  never the deployed flag.
- **The flag is not one-shot XOR-recoverable from the key.** Layer `i+1`'s key
  only exists *after* layer `i` is peeled (it is the `next_seed` inside layer
  `i`'s plaintext), so no single `ciphertext ⊕ keystream(X)` reveals it. The
  acceptance test asserts this directly.
- **Patching out the comparison is useless.** We prove this by `LD_PRELOAD`-ing
  a `memcmp` that always returns `0` (a real runtime defeat of the compare) and
  submitting a *wrong* key: the engine "accepts" and peels, but with the wrong
  `s₀ = SHA256("…R…"‖wrong key)` every layer decrypts to garbage — verified to
  be exactly the predicted wrong-peel bytes and never a valid flag. There is no
  partial-credit signal: a key that is 25/26 correct peels to pure garbage,
  identical in uselessness to one that is 0/26 correct.

---


## 6. Per-instance variation (operations)

Everything secret is in the `.car` image; the engine is identical for all teams.
`ZSCTF_SEED` drives a SHA-256 DRBG that varies: the S-box, the `R` matrices and
constants, `bkey`, the required key, the block graph (real slots + decoys +
opaque-predicate bytes), the entry block, `expected`, and the flag wrapping.
`L` and `R` also vary per instance. The acceptance test proves same-seed
byte-identity and different-seed divergence (including a different required
key). We do **not** claim cross-toolchain byte-identity of the compiled binary;
the reproducible property we assert is of the generated image (pure Python,
deterministic) and of the build under fixed gcc flags.

---


## 7. Distinct from the sibling rev challenges

| sibling | load-bearing mechanic | Carillon's difference |
|---------|-----------------------|-----------------------|
| **cogwork** | simple stack bytecode VM, plaintext bytecode, ISA recovery → straight-line invert | Carillon is **register**-based, bytecode is **encrypted** at rest, flow is **flattened** |
| **oxbow** | control-flow flattening + opaque predicates over a plaintext per-byte transform pipeline | Carillon adds **encrypted** bytecode, a **register ISA over GF(2⁸)**, and a check that is a **matrix system** not an op-by-op-invertible pipeline |
| **keywright** | linear keygen (solve a linear system) | Carillon's linear algebra is over **GF(2⁸)** and is wrapped by a **nonlinear S-box** each round and buried under a VM you must first recover and decrypt; the linear solve is one step, not the whole challenge |
| **lacquerbox** | Feistel network | Carillon is an SPN-style permutation, reached only through VM/bytecode recovery |
| **palimpsest** | Python bytecode | Carillon is native C, custom ISA, encrypted |

The **new** load-bearing mechanic is the combination: **runtime-decrypted
register bytecode + flattening + a GF(2⁸) SPN constraint you must model**. The
GF(2⁸) matrix inversion and S-box inversion are shared algebra, but they are not
reachable until the VM is recovered, the bytecode decrypted, and the system
modelled.

---


## 8. Lineage (reconstruction, `corpus-genome.yaml` + `system.html` §17)

- **oxbow** (sibling) — *borrowed:* control-flow flattening + opaque-predicate
  dispatch + decoy pruning + SHA-256 flag wrap. *Operator:* **GROUND** (the
  flattened dispatcher) and **GUARD-SWAP** (the key-independent predicates kept
  as deliberate, documented tautologies).
- **cogwork** (sibling) — *borrowed:* custom-ISA recovery from a stripped engine
  + `.image` container format. *Operator:* **SUBSTITUTE-TARGET** (stack VM →
  register VM) and **ELABORATE** (plaintext bytecode → runtime-decrypted
  bytecode).
- **keywright** (sibling) — *borrowed:* "the check is a system you solve, not a
  compare." *Operator:* **GENERALISE** (mod-256 linear → GF(2⁸) affine) +
  **GUARD-ADD** (a nonlinear S-box layer per round → an SPN, not a bare linear
  system).
- oxbow's writeup §8 explicitly tracked "key-dependent flow / per-instance
  opcode maps / an algebra-gated gear" as the **Extreme** extrapolation it did
  not build. Carillon builds the *algebra-gated gear* (the GF(2⁸) SPN) and the
  *runtime-decrypted bytecode*; it deliberately does **not** take the
  key-dependent-flow step (see §9 for why).

---


## 9. RED-TEAM / AI-RESISTANCE — honest band

**Why Extreme, honestly.** The band is justified by the *stacked* reverse
engineering the intended path requires before any maths is even possible:
recover a register ISA from a stripped binary; recognise and reproduce a
**per-block SHA-256 bytecode decryption** (without it the table is opaque);
reconstruct a **flattened** CFG through **opaque predicates** and **decoys**;
recognise **GF(2⁸)** arithmetic and its reduction polynomial; and then model the
lifted program as an **SPN** and invert it with **field linear algebra + inverse
S-box**. Each layer is individually known art; the Extreme rating is for the
*conjunction* and for the fact that the final check is a genuine **system to
model**, with **no gradient** to climb (the SHA-256 flag wrap means a
near-correct key is as useless as a random one).

**How a capable agent attacks it.** With a shell, a disassembler and Python:
`file`/`strings` the engine; disassemble; recognise the flattening dispatcher
and the `gfmul`/SHA-256 helpers; label the seven handlers and `pred`; script the
block decryption; lift the live path; segment at the S-box layers; recover the
matrices; invert over GF(2⁸). An agent that gets that far solves it. We state
that plainly — this is a hard crackme, not an unsolvable one.

**The honest shortcut (stated, not hidden).** The control flow is
**key-independent** — `pred` depends only on image bytes, never on the key. So a
solver does **not** have to reason about the opaque predicates or even the
bytecode decryption statically: it can run the engine once under a tracer
(`ltrace`/`gdb`/`qemu`/Pin) with *any* L-byte input and record the sequence of
*decrypted, executed* instructions straight off the trace. That collapses the
"encrypted + flattened" half of the challenge for anyone who realises the path
is input-independent. We chose key-independent flow deliberately to keep the
challenge **guessiness-0 and uniquely invertible**; the cost is this dynamic
shortcut, and we do not pretend otherwise. This is the same shortcut class
oxbow documented.

**Where the shortcut stops — the real differential vs oxbow.** In oxbow, once
you had the pipeline you inverted it trivially op by op. In Carillon, **the
trace hands you the program but not the key**: tracing with a wrong key gives
you the instruction sequence, but you still have to (a) recognise it as a
GF(2⁸) SPN, (b) lift the `GFMAC` stream into the matrices `A_r`, (c) invert
those matrices over the field, and (d) invert the S-box — all genuine modelling.
A dynamic trace with a *wrong* key never prints the flag; only inverting the
system yields the one correct key. So the shortcut removes the
decrypt-and-flatten busywork but **not** the modelling crux. That is the
intended Extreme core.

**Where an agent actually slips (silent, no-gradient traps).**

1. **Wrong field.** Reading `gfmul` as mod-256 multiply, or guessing the wrong
   reduction polynomial, yields matrices that invert to a wrong key with no
   error message.
2. **Instruction-by-instruction inversion.** The obvious "run the pipeline
   backwards" fails across the matrix multiply (`CLR`+accumulate is not locally
   invertible). An agent must *assemble* the matrix — the step that distinguishes
   modelling from peeling.
3. **Round order / S-box placement.** Applying `SBOX⁻¹` and `A⁻¹` in the wrong
   order, or off-by-one on the number of rounds `R`, silently produces garbage.
4. **Predicate polarity (static path).** Mapping `pk∈{0,1}`→`sB` vs
   `pk∈{2,3}`→`sA` backwards follows every decoy instead of the live path.
5. **Decryption index.** Using the wrong endianness or width for `u32le(i)` in
   the block keystream decrypts to noise.

None is conceptually deep, but each is a **silent** failure, and the SHA-256
wrap means there is **no partial-credit signal** to hill-climb on. An agent must
get the entire model right before it sees anything but `DENIED`.

**Is the resistance real?** It is **genuine and larger than oxbow's**, because
the modelling crux survives the dynamic shortcut (above). It is still not a wall
against a patient, correct agent — we do not claim it is. Its honest strength is
the conjunction of recovery layers plus a no-gradient, must-model-the-whole-
system final check.

**Contamination note.** This writeup now records the ISA, the opcode bytes, the
field polynomial, the predicate identities, the decryption formula, and the
default placeholder. An agent that ingested it can reproduce the *engine
semantics* from memory — but that is exactly what a human learns once, too. The
mitigation is structural: `ZSCTF_SEED` makes the S-box, matrices, `bkey`, block
graph, decoys, target and required key all per-instance, so memorised engine
semantics still force **per-instance** modelling. The acceptance test proves a
different seed yields a different required key. The *deployed flag* is never in
this document or any artifact — only the `REPLACE_ME_AT_DEPLOY` placeholder is.

**Human–AI differential.** Modest-to-moderate and specific: the no-gradient,
must-fully-model check penalises breadth-first "try many things" agent styles
more than the patient modeller; the field/round-order/decryption traps are
"looks right, is silently wrong" spots. For a genuinely AI-*resistant* version,
the tracked (unbuilt) step is **key-dependent control flow** — making `pred`
branch on key-derived state so the live path differs per input and a single
trace no longer linearises the program. We did **not** build that here because
done naively it breaks unique invertibility and introduces search/guessing;
doing it *carefully* (so the correct path is still uniquely recoverable) is the
next escalation and is called out rather than faked.

---


## 10. Unintended-path scan

We actively looked for cheaper wins than §4 and either closed them or documented
them:

- **`strings` / `grep` the flag.** Closed — the flag is split across nested
  encrypted layers; only the placeholder literal is embedded. (Acceptance test
  checks binary *and* image.)
- **One-shot XOR the flag out of the key.** Closed — the flag is a *nested*
  peel, not a single `ct ⊕ keystream(X)`; layer `i+1`'s key only exists after
  layer `i` is peeled (§12). The test asserts a one-shot XOR yields garbage.
- **Peel the wrong lane / stop early (the decoy, §12.4).** *Rejectable, not a
  win* — the decoy lane is checksum-consistent but assembles to a near-flag
  with an uppercase letter that fails the published strict validator; a partial
  peel fails it by shape. The reference solver escapes by exactly this format
  reasoning.
- **Patch/force the compare.** Closed as a flag path — `s₀` is derived from the
  submitted key, so forcing acceptance peels to garbage. Proven at runtime with
  an `LD_PRELOAD memcmp→0` shim (acceptance test).
- **Read the block table statically without decrypting.** Closed — the table is
  ciphertext; you must reproduce the per-block SHA-256 keystream.
- **Read blocks in file order / assume fallthrough.** Closed — the table is
  shuffled and padded with decoys; only the opaque-predicate live path is real.
- **Brute force the key.** Infeasible — `62^L` for `L∈{22,24,26}` over the
  printable alphabet (≥ 2¹³⁰), and there is no per-byte oracle.
- **Dynamic trace to linearise the program.** *Open and documented* (§9) — it
  recovers the instruction sequence but not the key; the GF(2⁸) SPN modelling
  and inversion still stand. This is the accepted, disclosed shortcut.
- **Guess `R`, the field, or round order.** Not an unintended *solve* — these
  are silent-failure traps, not shortcuts; getting them wrong yields `DENIED`,
  not a flag.
- **Algebraic weakness in the SPN.** Each `A_r` is a random invertible matrix
  (not low-rank / not structured) and the S-box is a full random permutation, so
  there is no linear-only attack that skips the S-box; the intended inversion is
  already the cheapest correct route once the program is lifted.

No unintended *flag-yielding* path was found beyond the disclosed dynamic
shortcut, which still requires the modelling crux.

---


## 11. Reproduce the acceptance test

```bash
# Linux (or Windows, which auto-bootstraps into WSL):
# -> 21/21 checks passed.
```

The test builds the engine, generates an instance, runs the **static** reference
solver, confirms the engine prints exactly the configured flag, exercises the
**nested flag-peel** (full real peel reconstructs the flag with every layer's
checksum passing; the full-decoy peel is checksum-consistent but assembles to a
near-flag that fails the strict validator; stopping early fails it; the flag is
*not* one-shot XOR-recoverable from the key), confirms a wrong key is declined,
proves the `LD_PRELOAD` compare-defeat yields garbage (the wrong peel), confirms
the flag is absent from binary and image, proves determinism (same seed identical
/ different seed divergent with a different required key), and proves the same
win over the TCP front-end.

---


## 12. Flag extraction 

**Assigned mechanism: LAYER-PEEL** (distinct from the secret-sharing,
blind-extraction, state-streaming, split-KDF and CRT mechanisms used elsewhere
in the catalog). This is the S2/S2a layer: solving the crux (recovering the key
`X` by GF(2⁸) SPN inversion — **unchanged**) earns you only the *means* to
extract; the flag then emerges solely by peeling nested layers.

### 12.1 Structure

The image's final section (after `expected[L]`) is:

```
u8 NL                                   # number of peel layers (4..7, per-instance)
for each layer i in 0..NL-1:
    u16 plen_d | u8 tag_d[4] | u8 ct_d[plen_d]     # DECOY lane
    u16 plen_r | u8 tag_r[4] | u8 ct_r[plen_r]     # REAL lane  (engine reads this)
```

Each lane is an independent **nested chain**. The opening seed of layer 0 is

```
s₀ = SHA256(label ‖ X)       label = "CARILLON-PEEL-v2|R|"  (real)
                                   = "CARILLON-PEEL-v2|D|"  (decoy)
```

Decrypting layer `i`'s ciphertext under `sᵢ` gives a plaintext

```
Pᵢ = fragmentᵢ (plenᵢ − 32 bytes)  ‖  next_seed (32 bytes)
```

`fragmentᵢ` is appended to the flag; `sᵢ₊₁ = next_seed`. **This is the nesting:**
`sᵢ₊₁` lives *inside* layer `i`'s plaintext, so layer `i+1` cannot be opened
until layer `i` is peeled — the flag is therefore **not** recoverable by a
single `ct ⊕ keystream(X)`.

### 12.2 Per-layer cipher (varied, not one scheme)

The cipher for a layer is chosen by `t = sᵢ[0] mod 3`, so different layers use
different primitives (all over the same SHA-256/GF machinery the challenge
already teaches):

- `t = 0` — **XOR keystream:** `ct = P ⊕ KS("X")`
- `t = 1` — **GF(2⁸) affine stream:** `ct[j] = gfmul(P[j], a[j]) ⊕ b[j]` with
  `a[j] = KS("A")[j] | 1` (forced invertible), `b[j] = KS("B")[j]`; inverse uses
  the field inverse `a[j]⁻¹`.
- `t = 2` — **add-mod-256 stream:** `ct[j] = (P[j] + KS("M")[j]) mod 256`.

where `KS(tag) = SHA256(sᵢ ‖ tag ‖ u64le(0)) ‖ SHA256(sᵢ ‖ tag ‖ u64le(1)) ‖ …`.

### 12.3 The per-layer gate (guess-exposure 0)

Each layer stores `tagᵢ = SHA256(sᵢ ‖ "T" ‖ Pᵢ)[:4]`. After decrypting a layer
the solver recomputes this and checks it: a correctly-opened layer verifies, a
mis-derived one does not. This is the verifiable checksum that makes every peel
step confirmable **by reasoning**, with no oracle and no guessing.

### 12.4 The decoy lane and its rejection tell

The decoy lane is a *fully checksum-consistent* parallel chain (all its `tag_d`
verify) whose fragments assemble to a **near-flag** of the form
`zerosecurectf{…}` containing **exactly one uppercase letter** — seed-derived
and **independent of the real flag** (it leaks nothing). Example observed on the
acceptance instance: `zerosecurectf{jkyzi9xs3xbvcSp0p9o}` (note the `S`).

Reachability / tell (R1 + R3): the two lanes are structurally identical, and the
decoy is stored **first** per layer, so a solver who grabs "the first ciphertext"
or mis-identifies the lane peels a chain where **every checksum passes** — not an
information-free dead end — yet the assembly **fails the published strict
validator** `^zerosecurectf\{[a-z0-9_]{8,48}\}$` on the uppercase letter. The
discriminator is the published format rule; the reference solver
(`extract_flag`) encodes exactly this reasoning — it returns the lane whose
checksums pass **and** whose assembly matches the validator. (The engine reads
lane index 1 unconditionally; disassembly confirms which lane is live.)

A **wrong peel** → a decoy fragment; a **fully-decoy peel** → the rejectable
near-flag; **stopping early** → a truncated string that fails the validator by
length/shape. All three are rejectable by reasoning (guess-exposure 0).

### 12.5 Why the invariants hold

- **Fully solvable:** `solution/solve.py` performs the entire peel after recovering
  `X` (see `peel_lane` / `extract_flag`); the test asserts the full real peel
  equals the configured flag with every checksum passing.
- **Crux unchanged:** the key is still recovered by lifting the VM and inverting
  the GF(2⁸) SPN; the peel is a strictly *additional* layer on top.
- **Patch-the-compare still cannot win:** the engine derives `s₀` from the
  *submitted* key, so forcing acceptance with a wrong key peels to the predicted
  garbage (asserted), never the flag.
- **Determinism / per-instance:** `NL`, the fragment partition, the per-layer
  cipher types, all seeds, and the decoy near-flag derive from the `ZSCTF_SEED`
  DRBG; same seed+flag ⇒ byte-identical image (asserted), different seed ⇒
  different layers *and* a different required key. (No cross-toolchain *binary*
  identity is claimed; the reproducible object is the generated image.)
- **Flag secrecy:** the flag never appears in the clear in the binary, the
  image, source, or compose — only the `REPLACE_ME_AT_DEPLOY` placeholder does.
