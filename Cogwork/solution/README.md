# Cogwork — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --image challenge/challenge.cog --bin challenge/cog
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Cogwork — official writeup

**Flag:** `zerosecurectf{c0gw0rk_unwound_one_gear_at_a_time}` (default seed; per-instance in production)

> Players receive only the stripped `cog` engine and their `challenge.cog`
> image. Everything below — the ISA, the image layout, the inverse of each gear
> — is what a solver *reconstructs*. It is written out here as the intended
> solution; none of it is handed to the player.


## 1. What you are looking at

`cog` is a tiny register-file virtual machine. It:

1. loads the `.cog` image (tables + bytecode program + comparison target + the
   XOR-wrapped flag),
2. reads your license key (one line, must be the exact length the image
   declares) into an `L`-byte register file,
3. runs the embedded program over that register file, and
4. compares the result to the embedded `expected[]`. A wrong key is `DENIED`
   and the engine exits. For the one correct key the engine switches into the
   **v2 ratchet generator** and streams the flag one character per correct
   per-notch token (see §4 and the organizer section).

The whole difficulty is step 3–4: recover what the program computes, then run it
backwards. The ratchet is a thin extraction layer on top of that unchanged crux.


## 2. The Cog ISA (recovered from the engine)

Every opcode transforms the **entire** register file `b[0..L-1]`. Instructions
are a 1-byte opcode, optionally followed by a 1-byte operand `k`.

| Opcode | Mnemonic | Operand | Effect on every `b[i]` |
|-------:|----------|:-------:|------------------------|
| `0x11` | `XORK`   | k | `b[i] ^= k` |
| `0x22` | `ADDK`   | k | `b[i] = (b[i] + k) mod 256` |
| `0x33` | `MULK`   | k | `b[i] = (b[i] * k) mod 256`  (`k` is always odd) |
| `0x44` | `ROLK`   | k | `b[i] = rol8(b[i], k mod 8)` |
| `0x55` | `ADDP`   | k | `b[i] = (b[i] + k*(i+1)) mod 256`  (position-dependent) |
| `0x66` | `SBOX`   | – | `b[i] = sbox[b[i]]` |
| `0x77` | `PERM`   | – | `out[i] = b[perm[i]]`  (position shuffle) |
| `0x88` | `CHN`    | k | for `i = 1..L-1`: `b[i] ^= rol8(b[i-1], k)`  (running chain) |
| `0x99` | `END`    | – | halt |

`rol8(v, r)` is an 8-bit left rotate by `r`.

### Image format (little-endian, v2)

```
"COGW" | u8 ver(=2) | u8 L | u16 flag_len | u16 prog_len
u8 sbox[256] | u8 perm[L] | u8 program[prog_len]
u8 expected[L] | u8 flag_ct[flag_len]
u8 decoy_seed[16] | u8 decoy_ct[flag_len]        (v2 ratchet trailer)
```

So the tables, the program, and the target are all *in the image, in the clear*.
What is **not** in the image is the key, or the flag in plaintext (see §4). The
v2 trailer (`decoy_seed` + `decoy_ct`) is what powers the ratchet
flag-extraction layer and the decoy near-flag (see §4 and the organizer section).


## 3. Why it inverts — the crux

Each of the nine gears is a **bijection** on the register file:

| Gear | Inverse |
|------|---------|
| `XORK k` | `XORK k` (self-inverse) |
| `ADDK k` | subtract `k`  (`ADDK (256-k)`) |
| `MULK k` | multiply by `k⁻¹ mod 256` (exists because `k` is odd) |
| `ROLK k` | rotate right by `k`  (`ROLK (8-k mod 8)`) |
| `ADDP k` | subtract `k*(i+1)` per position |
| `SBOX`   | apply the inverse S-box `sbox⁻¹` |
| `PERM`   | scatter back: `newb[perm[i]] = b[i]` |
| `CHN k`  | same op, iterated `i = L-1 .. 1` (the running chain unwinds high→low) |

A composition of bijections is a bijection, so the program as a whole is
invertible and `expected[]` has exactly **one** preimage: the correct key `X`.

> Recover `X` by starting from `expected[]` and applying the inverse of each
> instruction **in reverse program order**. No lattice, no brute force — the VM's
> own structure collapses the problem to one deterministic pass.

The two gears worth care:

- **`MULK`** is only invertible because the generator always picks an odd `k`
  (odd numbers are units mod 256). Its inverse multiplier is `pow(k, -1, 256)`.
- **`CHN`** uses the *already-updated* previous byte going forward, so its
  inverse must run from the high index down to 1; done that way, the byte it
  depends on has not yet been touched, exactly as in the forward pass.


## 4. The flag wrap — why you cannot cheat around the maths

In **v2** the flag is no longer released by a single one-shot XOR. Once the key
gate passes, the engine becomes a **ratchet generator** (see the organizer
section below for the exact math): it streams the flag one character per
correct per-notch token, where each notch is gated and each real keystream byte
is fused from both the running ratchet state (seeded from `X`) *and* the
submitted token. Consequences:

- **`strings` / memory dumps reveal nothing.** The plaintext flag is never in
  the binary or the image. (The acceptance test asserts this.)
- **No one-shot unwrap.** There is no `keystream(X)` you can XOR into `flag_ct`
  in a single pass — the per-character keystream depends on the whole state
  path. The acceptance test confirms the old one-shot unwrap now yields garbage.
- **Patching the comparison does not help.** If you NOP out the `expected[]`
  check so any key is accepted, a wrong key seeds a *wrong* ratchet state, so
  every computed token is wrong and every notch routes to the **decoy** branch;
  the real flag never appears. We verify this directly (LD_PRELOAD a
  `memcmp` that always matches + a wrong key → predicted garbage, never the
  flag). Preimage resistance means knowing the `zerosecurectf{` prefix leaks
  nothing about `X`, so there is no known-plaintext shortcut either.
- **The decoy is a trap.** Any wrong-token walk (e.g. feeding zero tokens)
  assembles to a fixed, per-instance *near-flag* that is length-shaped like a
  real flag but **fails** the strict `^zerosecurectf\{[a-z0-9_]{8,48}\}$`
  validator (it carries exactly one uppercase letter). A solver who does not
  recover the true token sequence gets this bait, not the flag.

The only path to the flag is the true key `X` (which generates the token
sequence), and the only cheap way to `X` is to invert the Cog program.


## Flag extraction 

This section documents the exact v2 ratchet so the ZSCTF team can audit and
reproduce the extraction layer. It is **not** handed to players. All labels,
offsets and the `i_LE32` (4-byte little-endian `i`) encoding match `gen.py`
(`ratchet_canonical`, `decoy_keystream`, `build_decoy_nearflag`) and `cog.c`
exactly; the acceptance test cross-checks the C engine against the Python
reference byte for byte.

**Constants.** `RATCHET_LABEL = b"cogwork-ratchet-v1|"`. `decoy_seed` is the
16-byte image trailer field; `i_LE32 = struct.pack("<I", i)`.

**The ratchet (correct path).** After the gear gate accepts the key `X`:

```
S_0      = SHA256(RATCHET_LABEL || X)
for i in 0 .. flag_len-1:
    tok_i   = SHA256(S_i || "t" || i_LE32)[:4]            # per-notch gate (4 bytes)
    # engine reads submitted token sub_i (one hex line, 8 nibbles -> 4 bytes)
    if sub_i == tok_i:                                    # correct notch
        emit_i = SHA256(S_i || sub_i || "e" || i_LE32)[0]
        out_i  = flag_ct[i] XOR emit_i                    # real flag char
    else:                                                 # wrong notch -> decoy
        dks_i  = SHA256(decoy_seed || "d" || i_LE32)[0]
        out_i  = decoy_ct[i] XOR dks_i                    # decoy char
    S_{i+1} = SHA256(S_i || sub_i || "a" || i_LE32)       # advance by SUBMITTED token
TRAIL    = hex(S_N[:4])                                   # printed after the stream
```

On the fully correct walk `sub_i == tok_i` for all `i`, so the state path and
the emitted bytes equal `gen.ratchet_canonical(X, flag_len)` and the stream is
the real flag; `flag_ct[i] = FLAG[i] XOR emit_i` from the generator closes the
loop. Offline, the solver skips the engine entirely: recover `X`, replay the
canonical ratchet, and XOR `emit_i` back out of `flag_ct`.

**TRAIL.** The engine prints `TRAIL <8 hex>` = the first 4 bytes of the final
state `S_N`. Because the advance folds in the *submitted* token, `S_N` (hence
the TRAIL) is a checksum of the entire walk: a single wrong/missing token
diverges it. The solver predicts `S_N[:4]` from `X` and asserts the engine's
TRAIL matches — a cheap integrity confirmation of a complete correct walk.

**The decoy near-flag (the tell).** The decoy branch is **token- and
state-independent** — it depends only on the public `decoy_seed` and the index
`i` — so *any* wrong-token walk (zeros, garbage, a partially-correct guess that
slips at one notch) assembles to exactly one fixed per-instance string:
`decoy_near[i] = decoy_ct[i] XOR SHA256(decoy_seed || "d" || i_LE32)[0]`.
`gen.build_decoy_nearflag` constructs this as `zerosecurectf{<body>}` with a
lowercase/`[a-z0-9_]` body of the right length, then flips **exactly one** body
character to uppercase. The result is length-valid and matches the loose shape
`^zerosecurectf\{.+\}$`, but **fails** the strict validator
`^zerosecurectf\{[a-z0-9_]{8,48}\}$` on that single uppercase letter. That
uppercase is the organizer tell: a submission that is a well-formed-looking
`zerosecurectf{...}` yet fails the strict regex is a decoy walk, not a real
solve. Guess-exposure stays **0**: the tokens come only from the recovered key
(not brute-forceable), and the TRAIL is a post-hoc checksum, not an oracle.


## 5. Step-by-step

1. Reverse `cog` to recover the nine opcode handlers (the ISA table in §2).
2. Parse `challenge.cog`: pull `L`, `sbox`, `perm`, `program`, `expected`.
3. Disassemble `program` into `(op, k)` instructions up to `END`.
4. Build `sbox⁻¹` and `perm⁻¹`.
5. Starting from `b = expected`, apply the §3 inverse of each instruction in
   reverse order → `b` is now the key `X`.
6. Sanity check: run the program forward on `X`; it must reproduce `expected`.
   (`X` also comes out as a clean printable string, which is a nice confirmation.)
7. Drive the **ratchet**: from `X` derive `S_0 = SHA256(RATCHET_LABEL || X)` and
   the per-notch token sequence (organizer section below). Feed the engine the
   key line followed by one `tok_i` (8 hex) per flag character; it streams the
   flag out notch by notch and ends with a `TRAIL` checksum. Equivalently,
   reconstruct the flag fully offline: `FLAG[i] = flag_ct[i] XOR emit_i`.

The reference solver [`solution/solve.py`](solution/solve.py) does exactly this —
inverting the gear-chain, reconstructing the flag offline, and (with `--bin`)
driving the engine through the ratchet and verifying the `TRAIL`:

```bash
python3 solution/solve.py --image challenge.cog --bin ./cog
```

Worked example (seed `demo-e2e`, flag `...ratchet_win_7b2e`): the solver recovers
the key `TKRLjRXGIfgviQASBVeIyHIg`, streams the flag through the engine, and the
engine `TRAIL` (`3fe5fb29`) matches the offline-predicted checksum.


## 6. Why the intended path is the only cheap one

- **No brute force.** `L` is 22–26 printable bytes; the key space is ≈ 62²² or
  more (> 10³⁹). Hopeless.
- **No per-byte attack.** `PERM` and `CHN` diffuse bytes into each other, so the
  positions are entangled — you cannot solve one byte at a time without first
  understanding and unwinding those two gears.
- **No `strings`, no patch, no known-plaintext** (see §4).
- **The program bytes are meaningless without the ISA**, so you genuinely have
  to reverse the engine. That is the load-bearing work, and it is reachable
  purely by reasoning about a small, clean machine — no guessing (ZSCTF §2
  invariants; low guess-exposure by design).


## 7. Design notes (for the ZSCTF team)

### Lineage (reconstruction, `corpus-genome.yaml` + `system.html` §17)

- **Seeds:** `zsctf-rev-005` *restless* (crux: "recover the semantics of a
  custom … VM") and `zsctf-rev-007` *revvm* (crux: "recover an unconventional
  custom ISA"); `zsctf-rev-006` *pass-it-on* is the same crux family. These are
  the custom-bytecode-VM seeds called out in the §17.5 worked example, where
  that crux is noted as typically H/P ("interesting but puzzle-flavoured").
- **Operators applied** (`system.html` §17.3 operator set):
  - `GROUND` (acts on G9/G3): attach a real scenario — a vendor's in-house
    VM-based *license validator*, the exact shape of real code-virtualization
    protectors (VMProtect/Themida-style handler VMs). This is *restless*'s own
    suggested affordance ("GROUND into real code-virtualization protector
    analysis"). Authenticity ↑↑, difficulty ~0.
  - `SUBSTITUTE-TARGET` (G3): the abstract "VM binary" becomes a concrete,
    stripped native crackme the player actually runs. Self-containment
    preserved.
  - `GUARD-SWAP` (G6): replace "obscurity of dispatch" with a **real
    mitigation** — a SHA-256-keyed flag wrap that defeats `strings` and binary
    patching, rather than security-by-obscurity. Authenticity ↑↑.
  - `PARAMETERISE` (any knob): expose `ZSCTF_SEED` so the S-box, permutation,
    program, target and required key are all per-instance — enabling unique
    team instances with no change to the crux.

  This is an interpolation-leaning reconstruction (`GROUND → SUBSTITUTE-TARGET →
  GUARD-SWAP → PARAMETERISE`), the authenticity-raising pattern named in §17.3.
  It deliberately does **not** `CHAIN` a second stage, keeping the challenge a
  single clean crackme.

- **Crux (load-bearing):** recovering the Cog ISA's semantics and recognising
  the program as an invertible pipeline. Trivialise it (e.g. hand over the ISA)
  and the challenge collapses — confirming it is load-bearing (§17.2).
- **Honest difficulty band:** **Hard**, not Extreme. The ISA is clean and
  unobfuscated and every gear is a textbook bijection; a competent reverser with
  the binary gets there. We do not inflate it.

### Harder variants (extrapolation, tracked but not built here)

- `PARAMETERISE` the ISA itself: per-instance opcode shuffling / handler
  duplication (what real VM protectors do) so the ISA must be re-derived per
  instance. Raises AI-resistance (defeats cross-instance ISA reuse). → toward
  Extreme.
- `SUBSTITUTE-PRIMITIVE` a non-invertible-looking gear whose inversion needs
  real algebra (e.g. an affine layer over `GF(2⁸)` plus an S-box, inverted by
  solving a small system) — still unique-preimage, more modelling.
- `CONCEAL-SHIFT` / `GUARD-SWAP`: add control flow (loops/branches) to the
  bytecode, anti-debug, or a packed engine. → toward Frontier.
- `CHAIN` (X): feed the recovered key into a second crux (e.g. it decrypts a
  second stage), the rev+forensics shape of the §17.5 example.


## 8. RED-TEAM / AI-RESISTANCE

**How a capable AI agent would attack this.** With tools (a shell, a
disassembler, Python) an agent's realistic pipeline is: run `strings`/`file` on
`cog`; disassemble it; identify a classic interpreter dispatch loop over a byte
stream; label the ~9 handlers (XOR/ADD/MUL/ROL/position-add/table-lookup/
permute/chained-XOR); parse the `.cog` container; then *script the inverse*. For
an agent that already recovers the handler semantics, writing the reverse pass
is mechanical — all nine inverses are standard. **An agent that gets that far
will solve it.** We state this plainly.

**Where an agent actually slips.** The resistance is real but *narrow*, and it
lives in the places where being fast and pattern-driven backfires:

1. **`MULK` inverse.** Agents frequently "undo" a multiply with a divide. Over
   `mod 256` that is wrong; the inverse is multiplication by the modular inverse
   of an odd constant. A division-based reverse pass fails silently (wrong key,
   `DENIED`) with no crash to debug.
2. **`CHN` direction.** The running chain must be unwound high-index→low; an
   agent that reverses it low→high (the "obvious" mirror) gets a subtly wrong
   preimage. Again it fails silently.
3. **`PERM` gather-vs-scatter.** `out[i] = b[perm[i]]` inverts by *scattering*
   (`newb[perm[i]] = b[i]`), not by applying the same permutation again. Easy to
   get backwards.
4. **Order.** Inverses must be applied in strict reverse program order; off-by-
   one framing of the instruction stream (variable-length operands) corrupts
   everything downstream.

None of these is conceptually hard, but each produces a silent wrong answer, and
the SHA-256 flag wrap (§4) means there is **no partial-credit signal** — a key
that is 23/24 correct unwraps to pure garbage, exactly like a key that is 0/24
correct. An agent cannot hill-climb; it must get the entire model right before
it sees anything but `DENIED`. That removes the feedback loop agents lean on.

**Is the resistance real, or just annoyance?** Honestly: it is *modest*. It is
genuine friction (the four silent-failure traps + no gradient to climb), but it
is not a wall against a careful agent. Its real strength is the next two points.

**Contamination note.** The ISA, opcode bytes, image format and the default-seed
key/flag above are now written down. An agent that has ingested this writeup can
reproduce the **default** instance from memory — that would be contamination,
not solving. The mitigation is structural: `ZSCTF_SEED` makes the S-box,
permutation, program, target and required key all per-instance, so a memorised
default (or a leaked solution for team A) yields nothing for team B. The
acceptance test proves divergence (different seed → different target and
different required key). What an agent *can* legitimately carry across instances
is the ISA itself — which a human learns once too — so per-instance variation
forces genuine per-instance modelling (`system.html` §9), not template recall.

**Human–AI differential.** This challenge does **not** claim a large differential
— it is a Hard crackme, and both strong humans and strong agents can finish it.
The intended differential is small and specific: (a) the no-gradient feedback
penalises the breadth-first, try-many-things agent style more than the patient
human who builds a correct mental model before running; (b) the modular-inverse
/ chain-direction / scatter traps are exactly the "looks obvious, is subtly
wrong" spots where fast pattern completion underperforms careful reasoning. For a
genuinely AI-*resistant* version, apply the §7 extrapolations (per-instance ISA
shuffling, an algebra-gated gear, control flow, anti-debug), which move the
agent's cost up super-linearly while leaving the human's mental model intact. We
flag that honestly rather than overclaiming resistance from the clean build.
