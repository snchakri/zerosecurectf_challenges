# Oxbow — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --image challenge/challenge.oxb
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Oxbow — official writeup

**Flag:** `zerosecurectf{0xb0w_cut_the_dead_bends_and_follow_the_river}` (default seed; per-instance in production)

> Players receive only the stripped `oxbow` engine and their `challenge.oxb`
> image. Everything below — the dispatcher, the block format, the edge
> selector, the per-byte transforms and their inverses — is what a solver
> *reconstructs*. It is written out here as the intended solution; none of it
> is handed to the player.


## 1. What you are looking at

`oxbow` is a tiny checker whose control flow has been **flattened**. There is no
straight-line sequence of operations; instead there is a single dispatch loop
over a table of small blocks:

```c
state = entry;
while (running) {
    run_block(state);          // one small transform on the L-byte buffer
    state = pred(pk,c) ? sA : sB;   // pick the next block
}
```

It:

1. loads the `.oxb` image (tables + block table + comparison target + the
   XOR-wrapped flag),
2. reads your license key (one line, must be the exact length the image
   declares) into an `L`-byte register file,
3. walks the flattened block graph from the entry block, running each visited
   block's transform over the register file, and
4. compares the result to the embedded `expected[]`. On a match it unwraps and
   prints the flag; otherwise it prints `DENIED`.

The whole difficulty is reconstructing **which blocks run, in what order** (step
3), recovering what that pipeline computes, then running it backwards (step 4).


## 2. The engine (recovered)

### Image format (little-endian)

```
"OXBW" | u8 ver | u8 L | u16 flag_len | u16 nblk | u8 entry | u8 rsv
u8 sbox[256]
u8 perm[L]
block[nblk]        (6 bytes each: op, k, sA, sB, pk, c)
u8 expected[L]
u8 flag_ct[flag_len]
```

So the tables, the block table and the target are all *in the image, in the
clear*. What is **not** in the image is the key, the real execution order
(you reconstruct it), or the flag in plaintext (see §5).

### Per-byte transforms

Each block runs one transform over the **entire** register file `b[0..L-1]`:

| Opcode | Mnemonic | Operand | Effect on every `b[i]` |
|-------:|----------|:-------:|------------------------|
| `0x00` | `END`    | – | halt |
| `0x11` | `XORK`   | k | `b[i] ^= k` |
| `0x22` | `ADDK`   | k | `b[i] = (b[i] + k) mod 256` |
| `0x33` | `MULK`   | k | `b[i] = (b[i] * k) mod 256`  (`k` always odd) |
| `0x44` | `ROLK`   | k | `b[i] = rol8(b[i], k mod 8)` |
| `0x55` | `ADDP`   | k | `b[i] = (b[i] + k*(i+1)) mod 256`  (position-dependent) |
| `0x66` | `XORP`   | k | `b[i] ^= (k + i) mod 256`  (position-dependent) |
| `0x77` | `SBOX`   | – | `b[i] = sbox[b[i]]` |
| `0x88` | `PERM`   | – | `out[i] = b[perm[i]]`  (position shuffle) |
| `0x99` | `CHN`    | k | for `i = 1..L-1`: `b[i] ^= rol8(b[i-1], k)`  (running chain) |

`rol8(v, r)` is an 8-bit left rotate by `r`.

### The edge selector — the flattening

After a block runs, the engine chooses its successor with

```c
state = pred(pk, c) ? sA : sB;
```

where `pred` depends **only on the per-block byte `c`** (not on the key or the
buffer):

```c
pred(pk,c):  x = c
  pk==0 -> (x*x - x) & 1
  pk==1 -> (x*x + x) & 1
  pk==2 -> ((x*x - x) & 1) ^ 1
  pk==3 -> (x*x + x + 1) & 1
```

These are **opaque predicates**. `x*x - x = x(x-1)` and `x*x + x = x(x+1)` are
each a product of two consecutive integers, hence **always even**, so:

- `pk ∈ {0,1}` → the predicate is **always 0** → the live edge is always `sB`;
- `pk ∈ {2,3}` → the predicate is **always 1** → the live edge is always `sA`.

The compiler cannot prove this at `-O2` (the parity of `x(x±1)` is not folded),
so in the stripped binary each selector looks like a genuine data-dependent
branch computing a parity of a product. It is not: once you recognise the
number-theoretic identity, every block has exactly **one** live successor. The
other edge points to a **decoy** block — a plausible-looking transform that the
river never reaches (an "oxbow": a bend cut off from the stream).


## 3. Reconstructing the real pipeline — the crux

Start at `entry`. At each block, evaluate `pred(pk, c)` (statically — it is a
constant per block), follow the live edge, and record the block's `(op, k)`.
Stop at the `END` block. The blocks you never touch are decoys; drop them. What
remains is a straight-line pipeline of per-byte transforms.

Two ways this goes wrong if you are careless:

- **Following the wrong edge.** A solver that assumes "fallthrough" (block *i*
  then block *i+1* in table order) or that always follows `sA`/`sB` reconstructs
  a different pipeline and derives a wrong key. The block table is shuffled;
  table order is meaningless. (The acceptance test proves a naive edge-follow
  does not recover the real pipeline.)
- **Treating decoys as live.** Both edges look real in the disassembly. Only by
  resolving the opaque predicate do you learn which one is taken.


## 4. Why it inverts

Every transform is a **bijection** on the register file:

| Op | Inverse |
|----|---------|
| `XORK k` | `XORK k` (self-inverse) |
| `ADDK k` | subtract `k` |
| `MULK k` | multiply by `k⁻¹ mod 256` (exists because `k` is odd) |
| `ROLK k` | rotate right by `k` |
| `ADDP k` | subtract `k*(i+1)` per position |
| `XORP k` | `XORP k` (self-inverse per position) |
| `SBOX`   | apply the inverse S-box `sbox⁻¹` |
| `PERM`   | scatter back: `newb[perm[i]] = b[i]` |
| `CHN k`  | same op iterated `i = L-1 .. 1` (the running chain unwinds high→low) |

A composition of bijections is a bijection, so the recovered pipeline has
exactly **one** preimage of `expected[]`: the correct key `X`. Recover `X` by
starting from `expected[]` and applying the inverse of each transform **in
reverse pipeline order**. No lattice, no brute force.

The gears worth care are the same three that bite in any invertible-pipeline
rev: `MULK` inverts by the **modular inverse** of an odd constant (not a
divide); `CHN` must be unwound **high index → low**; `PERM` inverts by
**scattering**, not by re-applying the same permutation.


## 5. The flag wrap — why you cannot cheat around the maths

The flag is stored as

```
flag_ct[i] = FLAG[i] XOR keystream(X)[i]
keystream(X) = SHA256(X || 0x00) || SHA256(X || 0x01) || ...   (truncated)
```

keyed on the **correct key `X` itself**. At run time the engine computes
`keystream(your_key)` and XORs it into `flag_ct`. Consequences:

- **`strings` / memory dumps reveal nothing.** The plaintext flag is never in
  the binary or the image. (The acceptance test asserts this.)
- **Patching the comparison does not help.** NOP out the `expected[]` check so
  the engine always prints, and a wrong key still produces
  `keystream(wrong_key)` — a hash of the wrong input — which unwraps `flag_ct`
  to garbage. Knowing the `zerosecurectf{` prefix leaks nothing about `X`
  (SHA-256 preimage resistance), so there is no known-plaintext shortcut.

The only path to the flag is the true key `X`, and the only cheap way to `X` is
to reconstruct the real pipeline and invert it.


## 6. Step-by-step

1. Reverse `oxbow`: find the dispatch loop, the 6-byte block format, the ten
   opcode handlers, and the edge selector `pred(pk, c)`.
2. Parse `challenge.oxb`: `L`, `entry`, `nblk`, `sbox`, `perm`, the block table,
   `expected`.
3. Resolve each opaque predicate; from `entry`, follow the live edge to `END`,
   collecting the real `(op, k)` pipeline. Ignore decoys.
4. Build `sbox⁻¹`; from `b = expected`, apply the §4 inverse of each op in
   reverse order → `b` is the key `X`.
5. Sanity: run the pipeline forward on `X`; it must reproduce `expected`.
   (`X` also comes out a clean printable string — a nice confirmation.)
6. `printf '%s' "$X" | ./oxbow challenge.oxb` → the flag.

The reference solver [`solution/solve.py`](solution/solve.py) does exactly this and
also drives the engine to print the flag:

```bash
python3 solution/solve.py --image challenge.oxb --bin ./oxbow
```

Worked example (default seed): the solver reports `real pipeline length: 24 ops
(51 blocks total in image, 26 decoys)`, recovers the key
`MNVI0xMnxYNhgkGdCse7yQ`, and the engine returns the flag.


## 7. Why the intended path is the only cheap one

- **No brute force.** `L` is 22–26 printable bytes; the key space is ≈ 62²² or
  more (> 10³⁹). Hopeless.
- **No per-byte attack.** `PERM`, `CHN`, `ADDP` and `XORP` entangle positions,
  so you cannot solve one byte at a time without first unwinding the pipeline.
- **No `strings`, no patch, no known-plaintext** (see §5).
- **The block bytes are meaningless without the real order**, which is hidden
  behind the flattening + opaque predicates. That is the load-bearing work, and
  it is reachable purely by reasoning — no guessing (ZSCTF §2 invariants; low
  guess-exposure by design).


## 8. Design notes (for the ZSCTF team)

### Distinct from the sibling rev challenges

Oxbow deliberately does **not** repeat the crux of the existing rev set:

- **cogwork** — recover a custom bytecode **VM's ISA** and invert a *straight-
  line* program.
- **keywright** — solve a **linear system** keygen.
- **palimpsest** — reverse **Python bytecode**.

Oxbow's crux is **control-flow reconstruction**: the operation *sequence* is
hidden by control-flow flattening and opaque-predicate decoys, and must be
recovered before any inversion is possible. The inversion that follows is
standard invertible-pipeline algebra (shared vocabulary with the family), but it
is downstream of the new, load-bearing part.

### Lineage (reconstruction, `corpus-genome.yaml` + `system.html` §17)

- **Seeds:**
  - `zsctf-rev-010` *y0da* — crux "reconstruct control flow from jump-chained
    code fragments", guard "fragmentation interleaved with benign code". The
    flattened dispatcher + decoy blocks are a GROUNDed, benign realisation of
    that crux.
  - `zsctf-rev-011` *serpentine* — crux "follow … control flow through crafted
    … handlers", guard "obfuscation + encryption". Donates the "follow the one
    real control path among crafted misdirection" shape (its genome lists
    `SUBSTITUTE-TARGET` and `GROUND` as affordances).
- **Operators applied** (`system.html` §17.3 operator set):
  - `SUBSTITUTE-TARGET` (G3): carry the control-flow-reconstruction crux from a
    Windows anti-analysis binary onto a small, self-contained, portable
    C crackme a player runs directly. Self-containment preserved.
  - `GROUND` (G9/G3): frame it as a vendor's flattened license checker — the
    exact shape of commercial control-flow-flattening obfuscators (OLLVM-style
    `-fla`, VM/flattening protectors). Authenticity ↑↑, difficulty ~0.
  - `GUARD-SWAP` (G6): replace *fragmentation-as-obscurity* with two **real**
    mitigations — (a) genuine opaque predicates (number-theoretic tautologies a
    compiler cannot fold), and (b) a SHA-256-keyed flag wrap defeating `strings`
    and patching. Authenticity ↑↑.
  - `PARAMETERISE` (any knob): expose `ZSCTF_SEED` so the S-box, permutation,
    block graph, decoys, target and required key are all per-instance.

  This is an interpolation-leaning reconstruction (`SUBSTITUTE-TARGET → GROUND →
  GUARD-SWAP → PARAMETERISE`), the authenticity-raising pattern named in §17.3.
  It deliberately does **not** `CHAIN` a second stage, keeping it a single clean
  crackme.

- **Crux (load-bearing):** reconstructing the live control path through the
  flattened, opaque-predicate-gated block graph. Trivialise it (hand over the
  real op order) and the challenge collapses to a routine inversion — confirming
  it is load-bearing (§17.2). The acceptance test's "naive edge-follow" check is
  a built-in mutation test of exactly this.
- **Honest difficulty band:** **Hard**, not Extreme. The flattening is clean and
  the predicates are standard tautologies; a competent reverser with the binary
  gets there. We do not inflate it (§8 red-team is explicit about the shortcut).

### Harder variants (extrapolation, tracked but not built here)

- **Key-dependent control flow.** Make some predicates depend on the buffer so
  the path branches per key. This would raise resistance to single-trace
  recovery, but risks breaking clean invertibility / introducing guessiness, so
  it is *not* used here (kept guessiness 0). → toward Extreme, with care.
- `PARAMETERISE` the opcode map per instance (as cogwork's extrapolation notes)
  so the handler semantics must be re-derived too.
- `SUBSTITUTE-PRIMITIVE` an algebra-gated transform (affine layer over GF(2⁸))
  that needs a small linear solve to invert.
- `CONCEAL-SHIFT` / anti-debug / a packed engine. → toward Frontier.
- `CHAIN` (X): feed the recovered key into a second-stage decrypt.


## 9. RED-TEAM / AI-RESISTANCE — honest band

**How a capable AI agent would attack this.** With a shell, a disassembler and
Python, the realistic pipeline is: `file`/`strings` the engine; disassemble it;
recognise a control-flow-flattening dispatcher (a `while` loop over a
`switch(state)` with a computed next-state); label the ten per-byte handlers and
the edge selector; parse the `.oxb` container; reconstruct the live path; then
script the inverse. **An agent that gets that far will solve it. We state this
plainly.**

**The honest shortcut (stated, not hidden).** The control flow here is
**key-independent** — `pred` depends only on the image byte `c`, never on the
buffer. So an agent does **not** have to reason about the opaque predicates at
all: it can run the engine once under a tracer (ltrace/gdb/Pin/QEMU) with *any*
22–26-byte input, record the sequence of blocks the dispatcher visits, and read
the real pipeline straight off the trace. This collapses the "flattening" half
of the challenge for anyone who realises the path is input-independent. We chose
key-independent flow deliberately to keep the challenge a clean, guessiness-0,
uniquely-invertible crackme; the cost is this dynamic shortcut, and we do not
pretend otherwise. A static-only solver must instead recognise the
tautologies — which is the intended (and more instructive) path.

**Where an agent actually slips.** The resistance is real but *narrow*:

1. **Trusting table order.** The block table is shuffled and padded with decoys.
   An agent that disassembles the dispatcher and reads blocks in file order, or
   assumes fallthrough, reconstructs the wrong pipeline. The decoys are chosen to
   be plausible transforms, so the wrong pipeline still "runs".
2. **Opaque-predicate direction (static path).** Mapping `pk ∈ {0,1}` to the
   `sB` edge and `pk ∈ {2,3}` to the `sA` edge requires actually evaluating the
   parity identity; guessing the polarity backwards follows every decoy instead.
3. **`MULK` inverse** via modular inverse, not division (silent wrong key).
4. **`CHN` direction** must unwind high→low; the "obvious" low→high mirror is
   subtly wrong.
5. **`PERM` gather-vs-scatter** — invert by scattering, not re-permuting.

None is conceptually hard, but each produces a **silent** wrong answer, and the
SHA-256 flag wrap (§5) means there is **no partial-credit signal** — a key that
is 23/24 correct unwraps to pure garbage, exactly like one that is 0/24 correct.
An agent cannot hill-climb; it must get the entire model right before it sees
anything but `DENIED`. That removes the feedback loop agents lean on.

**Is the resistance real, or just annoyance?** Honestly: it is *modest*. It is
genuine friction (control-flow reconstruction + four silent-failure traps + no
gradient to climb), but it is **not** a wall against a careful agent, especially
one that spots the dynamic-tracing shortcut. Its real strength is the next two
points.

**Contamination note.** The engine design, opcode bytes, image format, the
predicate identities and the default-seed key/flag above are now written down.
An agent that ingested this writeup can reproduce the **default** instance from
memory — that is contamination, not solving. The mitigation is structural:
`ZSCTF_SEED` makes the S-box, permutation, block graph, decoy set, target and
required key all per-instance, so a memorised default (or a leaked solution for
team A) yields nothing for team B. The acceptance test proves divergence
(different seed → different target and different required key). What an agent
*can* legitimately carry across instances is the engine's semantics — which a
human learns once too — so per-instance variation forces genuine per-instance
modelling (`system.html` §9), not template recall.

**Human–AI differential.** This challenge does **not** claim a large
differential — it is a Hard crackme, and both strong humans and strong agents
can finish it. The intended differential is small and specific: (a) the
no-gradient feedback penalises the breadth-first, try-many-things agent style
more than the patient human who builds a correct mental model before running;
(b) the table-order / predicate-polarity / modular-inverse / chain-direction /
scatter traps are exactly the "looks obvious, is subtly wrong" spots where fast
pattern completion underperforms careful reasoning. For a genuinely
AI-*resistant* version, apply the §8 extrapolations (key-dependent flow done
carefully, per-instance opcode maps, an algebra-gated gear, anti-debug), which
move the agent's cost up super-linearly while leaving the human's mental model
intact. We flag that honestly rather than overclaiming resistance from this
clean build.

## Archived engine mismatch

The supplied image is version 1, while the archived engine expects version 2 and rejects it with `bad slot table`. The solver recovers the key by inverting the live pipeline and decodes the version 1 SHA-256 wrap directly. Both original artifacts are preserved; no claim is made that the mismatched engine can run this image.
