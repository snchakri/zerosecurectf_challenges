# Palimpsest — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python3.13 solution/solve.py --image challenge/palimpsest.pyc --run
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Palimpsest — official writeup

**Flag:** `zerosecurectf{p4l1mps3st_th3_s0urc3_1s_g0n3_byt3c0d3_rem41ns}`
(default seed `palimpsest-demo-0001`; per-instance in production)

**Default-seed worked example:** license key `gBQStguuXcx8Zh1IGTywklS1` (length 24)
activates the shipped `challenge/palimpsest.pyc` and prints the flag above.

> Players receive only their team's `palimpsest.pyc` — a marshalled CPython 3.13
> code object. Everything below — the activation logic, the image layout, the
> inverse of each layer — is what a solver *reconstructs by reading the
> bytecode*. The `.py` source is never shipped. It is written out here as the
> intended solution.


## 1. What you are looking at

`palimpsest.pyc` is a standard `.pyc`: a 16-byte header followed by a marshalled
code object.

```
bytes  0.. 3   magic number        (CPython 3.13 == f3 0d 0d 0a)
bytes  4.. 7   bit field           (0 here -> timestamp-based)
bytes  8..11   mtime               (pinned to 0 for reproducibility)
bytes 12..15   source size         (pinned to 0)
bytes 16..      marshal.dumps(code object)
```

Load it with the standard library — no third-party tools, and (importantly)
**no decompiler**, because none supports 3.13 bytecode:

```python
import marshal
code = marshal.loads(open("palimpsest.pyc", "rb").read()[16:])
```

The tool, when run directly (`python3 palimpsest.pyc`), reads one line from
stdin as the candidate license key, runs an activation gate over it, and either
prints the flag (on the one correct key) or `DENIED`.


## 2. Reading the gate (`dis`)

The module defines a handful of nested helper functions — they live as code
objects inside `code.co_consts`, and `dis.dis(code)` recurses into them. The
module-level constants (the per-instance tables) sit right at the top as simple
`NAME = <bytes literal>` assignments. Reconstructed, the gate is:

```python
L        # input length (24/28/32 this instance)
SBOX     # 256-byte bijection
PERM     # L-byte position permutation
ADD, XOR # L-byte per-position keys
MUL      # one odd byte (a unit mod 256)
EXPECTED # L-byte comparison target
FLAG_CT  # the key-wrapped flag
ROT = (SBOX[7] % 7) + 1      # COMPUTED at run time, not stored

def _transform(key):          # bytearray, all arithmetic mod 256
    b = _affine(b)            # b[i] = (b[i] + ADD[i]) & 255 ; then b[i] ^= XOR[i]
    b = _mix(b)              # b[i] = (b[i] * MUL) & 255
    b = _sub(b)             # b[i] = SBOX[b[i]]
    b = _diffuse(b)          # for i in 1..L-1: b[i] ^= rol8(b[i-1], ROT)
    b = _permute(b)          # out[i] = b[PERM[i]]
    return bytes(b)

def _activate(key):
    if len(key) != L:            return None
    if _transform(key) != EXPECTED: return None
    return FLAG_CT XOR keystream(key)     # keystream = SHA256(key||0)||SHA256(key||1)||...
```

What the disassembly actually looks like (the diffusion chain, from the default
image — `solution/solve.py --disasm` prints the whole thing):

```
_diffuse:
  LOAD_GLOBAL  range;  LOAD_CONST 1;  LOAD_GLOBAL L;  CALL 2;  GET_ITER      # for i in range(1, L)
  FOR_ITER ...
    LOAD_FAST_LOAD_FAST (b, i); COPY 2; COPY 2; BINARY_SUBSCR               # b[i]
    LOAD_GLOBAL _rol8; LOAD_FAST_LOAD_FAST (b, i); LOAD_CONST 1; BINARY_OP - # _rol8(b[i-1], ...)
    BINARY_SUBSCR; LOAD_GLOBAL ROT; CALL 2
    BINARY_OP 25 (^=); ... STORE_SUBSCR                                      # b[i] ^= ...
```

You do not need to turn this back into pretty Python — you need to be sure of
exactly four things: which layers run and in what order, the rotate amount and
that the chain reads the *updated* previous byte, that `_permute` is a **gather**
(`out[i] = b[perm[i]]`), and that `MUL` is a multiply, not a shift.

### Pulling the constants out mechanically

The per-instance tables are module globals, so in the top-level bytecode each is
a single `LOAD_CONST <bytes>` immediately followed by `STORE_NAME <name>`. Walk
the instructions and pair them — no need to execute the (untrusted) artifact:

```python
import dis
g, last = {}, None
for ins in dis.get_instructions(code):
    if ins.opname == "LOAD_CONST":  last = ins.argval
    elif ins.opname == "STORE_NAME": g[ins.argval] = last
# g now has L, SBOX, PERM, ADD, XOR, MUL, EXPECTED, FLAG_CT
```

(`ROT` is computed, not stored, so reproduce `(SBOX[7] % 7) + 1` yourself.)


## 3. Why it inverts — the crux

Each layer is a **bijection** on the register file, so the whole gate is a
bijection and `EXPECTED[]` has exactly **one** preimage: the correct key `X`.
Recover `X` by starting from `EXPECTED[]` and applying the inverse of each layer
**in reverse order**:

| Layer (forward) | Inverse (applied in reverse order) |
|-----------------|------------------------------------|
| `_permute`: `out[i] = b[perm[i]]` | **scatter** back: `b[perm[i]] = out[i]` (not re-applying perm) |
| `_diffuse`: `for i=1..L-1: b[i]^=rol8(b[i-1],ROT)` | same op, iterated `i = L-1 .. 1` (unwind **high→low**) |
| `_sub`: `b[i]=SBOX[b[i]]` | inverse S-box `SBOX⁻¹` |
| `_mix`: `b[i]=(b[i]*MUL)&255` | multiply by `pow(MUL, -1, 256)` (MUL is odd → a unit; **not** a divide) |
| `_affine`: add then xor | **xor first**, then subtract: `b[i]^=XOR[i]; b[i]=(b[i]-ADD[i])&255` |

No lattice, no brute force — the structure collapses the problem to one
deterministic pass. The full routine is `invert()` in `solution/solve.py`; a
one-line self-check (`forward(X) == EXPECTED`) confirms you got every subtlety
right before you ever run the tool.


## 4. The flag wrap — why you cannot cheat around the maths

The flag is stored as

```
FLAG_CT[i] = FLAG[i] XOR keystream(X)[i]
keystream(X) = SHA256(X || 0x00) || SHA256(X || 0x01) || ...   (truncated)
```

keyed on the **correct key `X` itself**. At run time the tool computes
`keystream(your_key)` and XORs it into `FLAG_CT`. Consequences:

- **`strings` / memory dumps reveal nothing.** The plaintext flag is never in
  the image. (The acceptance test asserts this: neither the flag nor the
  `zerosecurectf{` prefix appears in the bytes.)
- **Patching the comparison does not help.** If you NOP out the
  `_transform(key) != EXPECTED` check so the tool always unwraps, a wrong key
  still produces `keystream(wrong_key)` — a hash of the wrong input — and
  unwraps `FLAG_CT` to garbage. The test proves this directly (forcing the
  unwrap with a wrong key yields non-flag bytes). Because `keystream` is a
  SHA-256 of the key, the known `zerosecurectf{` prefix leaks nothing about `X`
  (preimage resistance), so there is no known-plaintext shortcut either.

The only path to the flag is the true key `X`, and the only cheap way to `X` is
to read the bytecode and invert the gate.


## 5. Step-by-step

1. `marshal.loads(pyc[16:])` → the module code object.
2. Disassemble it (and its nested code objects) with `dis`; recover the five
   layers, their order, `ROT = (SBOX[7] % 7) + 1`, and the gather-style `_permute`.
3. Pull `L, SBOX, PERM, ADD, XOR, MUL, EXPECTED` out of the module-level
   `LOAD_CONST`/`STORE_NAME` pairs; build `SBOX⁻¹` and `MUL⁻¹ mod 256`.
4. Start from `b = EXPECTED` and apply the §3 inverses in reverse order → `X`.
5. Self-check: run the gate forward on `X`; it must reproduce `EXPECTED` (and
   `X` comes out as a clean printable string — a nice confirmation).
6. `printf '%s' "$X" | python3 palimpsest.pyc` → the flag.

```bash
python3 solution/solve.py --image palimpsest.pyc --run
# [+] recovered license key: gBQStguuXcx8Zh1IGTywklS1
# [+] FLAG = zerosecurectf{p4l1mps3st_th3_s0urc3_1s_g0n3_byt3c0d3_rem41ns}
```


## 6. Why the intended path is the only cheap one

- **No brute force.** `L` is 24–32 printable bytes; the key space is ≈ 62²⁴ or
  more (> 10⁴²). Hopeless.
- **No per-byte attack.** `_diffuse` and `_permute` entangle the positions, so
  you cannot solve one byte at a time without first unwinding those two layers.
- **No `strings`, no patch, no known-plaintext** (see §4).
- **No decompiler.** 3.13 bytecode has no working source recovery tool, so the
  logic genuinely has to be read from the disassembly — that is the
  load-bearing work, and it is reachable purely by reasoning about a small,
  clean module (no guessing; ZSCTF §2 invariants, guess-exposure 0).


## 7. Design notes (for the ZSCTF team)

### Lineage (reconstruction, `corpus-genome.yaml` + `system.html` §17)

- **Seeds:**
  - `zsctf-rev-016` *"The challenge that shall not be named"* — crux "unpack and
    analyse a protected Python backdoor", target *PyInstaller/PyArmor-packed
    Python*; its listed affordances are exactly `SUBSTITUTE-TARGET` and
    `PARAMETERISE`, and its reconstruct note is "per-instance repack; close the
    shortcuts the author noted".
  - `zsctf-rev-005` *restless* — crux "recover the semantics of a … custom VM",
    affordance `GROUND` → "real code-virtualization protector analysis".
- **Operators applied** (`system.html` §17.3 operator set):
  - **`SUBSTITUTE-TARGET`** (acts on G3, Δdifficulty ≈ 0, risk = self-containment):
    swap rev-016's heavy *PyInstaller/PyArmor-packed* target for a **plain
    marshalled 3.13 `.pyc` code object**. The crux — *recover validation logic
    from compiled Python* — is preserved; the packer, anti-analysis and
    weaponizable backdoor framing are dropped, which keeps the challenge benign,
    pure-stdlib and self-contained (the invariant SUBSTITUTE-TARGET most risks).
  - **`GROUND`** (acts on G9/G3, Δdifficulty ≈ 0, authenticity ↑↑): attach a real
    scenario — a vendor shipping a **licensed tool as `.pyc`-only** to conceal
    its activation check, the everyday practice *restless*'s GROUND affordance
    points at. Here the "machine whose semantics you recover" is **CPython
    itself**, and its bytecode is the thing to read.
  - **`PARAMETERISE`** (rev-016's own affordance): expose `ZSCTF_SEED` so the
    S-box, permutation, ADD/XOR keys, multiplier, rotate, required key, target
    and flag-wrap are all per-instance — unique team instances with no change to
    the crux.
  - A **GUARD-SWAP**-flavoured detail (as in sibling *Cogwork*): the barrier is a
    **real key-bound mitigation** — the SHA-256 flag wrap that defeats `strings`
    and bytecode patching — rather than security-by-obscurity (CWE-656 avoided).

  This is an interpolation-leaning reconstruction (`SUBSTITUTE-TARGET → GROUND →
  PARAMETERISE`), the authenticity-raising pattern named in §17.3. It
  deliberately does **not** `CHAIN` a second stage, keeping it a single clean
  crackme.

- **Crux (load-bearing):** reading the activation logic out of the 3.13 bytecode
  and recognising it as an invertible pipeline. Trivialise it (hand over the
  `.py`) and the challenge collapses — confirming it is load-bearing (§17.2).

- **Sibling note.** Palimpsest is the Python-bytecode counterpart of *Cogwork*
  (native custom-VM). Same invertible-pipeline crux *family*; different medium —
  there the player recovers a custom ISA from a stripped native binary, here the
  "ISA" is CPython's (documented) and the work is fluently reading real 3.13
  bytecode with no decompiler to lean on.

- **Honest difficulty band: Hard**, not Extreme. The module is clean and
  unobfuscated, the ISA is CPython's own, and every layer is a textbook
  bijection; a competent reverser who can read 3.13 bytecode gets there. We do
  not inflate it.

### Harder variants (extrapolation, tracked but not built here)

- `PARAMETERISE` the **logic shape** itself: per-instance layer order / which
  ops appear / handler duplication (what real Python obfuscators do), so the
  pipeline must be re-read per instance rather than recognised once. Raises
  AI-resistance (defeats cross-instance structure reuse). → toward Extreme.
- `GUARD-SWAP` / `CONCEAL-SHIFT`: actually pack it (PyArmor/PyInstaller),
  obfuscate the bytecode (opaque predicates, `dis`-hostile jumps), or add
  anti-analysis — i.e. walk back toward the rev-016 target. → toward Frontier.
- `SUBSTITUTE-PRIMITIVE` a layer whose inversion needs real algebra (e.g. an
  affine layer over `GF(2⁸)` inverted by solving a small system) — still
  unique-preimage, more modelling.
- `CHAIN` (X): feed the recovered key into a second crux (it decrypts a second
  stage), the rev+forensics shape of the §17.5 example.


## 8. RED-TEAM / AI-RESISTANCE

**Honest band: Hard.** Both strong humans and strong agents can finish this. We
state the resistance plainly and do not overclaim.

**How a capable AI agent would attack this.** With a shell and Python an agent's
realistic pipeline is: `file`/`xxd` the `.pyc`; recognise the 3.13 magic; strip
16 bytes and `marshal.loads`; `dis.dis` the module and its nested code objects;
label the five layers; dump the module constants; script the inverse. For an
agent that already reads CPython bytecode fluently, the reverse pass is
mechanical — all five inverses are standard. **An agent that gets that far will
solve it.** The genuine filter is bytecode-reading fluency on **3.13**
specifically: there is no decompiler, so an agent (or human) that leans on
`uncompyle6`/`decompyle3` gets nothing and must read the disassembly directly.

**Where an agent actually slips.** The resistance is real but *narrow*, and it
lives where being fast and pattern-driven backfires — each of these fails
**silently** (wrong key → `DENIED`, no crash to debug):

1. **`MUL` inverse.** Agents frequently "undo" a multiply with a divide. Over
   mod 256 that is wrong; the inverse is multiplication by the modular inverse of
   an odd constant (`pow(MUL, -1, 256)`).
2. **`_diffuse` direction.** The running chain must be unwound high-index→low; an
   agent that reverses it low→high (the "obvious" mirror) gets a subtly wrong
   preimage.
3. **`_permute` gather-vs-scatter.** `out[i] = b[perm[i]]` inverts by
   *scattering* (`b[perm[i]] = out[i]`), **not** by applying the permutation
   again.
4. **`ROT` is computed, not stored.** `ROT = (SBOX[7] % 7) + 1`. An agent that
   only dumps literal constants and never traces that one expression uses the
   wrong rotate and fails silently.
5. **Order / affine sub-order.** Inverses must be applied in strict reverse
   order, and within `_affine` the undo is *xor then subtract*. Off-by-one
   framing of the variable-length bytecode, or getting that sub-order wrong,
   corrupts everything downstream.

The SHA-256 flag wrap (§4) means there is **no partial-credit signal** — a key
that is 23/24 correct unwraps to pure garbage, exactly like a key that is 0/24
correct. An agent cannot hill-climb; it must get the entire model right before
it sees anything but `DENIED`. That removes the feedback loop agents lean on.

**Is the resistance real, or just annoyance?** Honestly: it is *modest*. It is
genuine friction (the five silent-failure traps + no gradient to climb + no
decompiler), but it is not a wall against a careful agent. Its real strength is
the next two points.

**Contamination note.** The logic, the layer order, the image layout, and the
default-seed key/flag above are now written down. An agent that has ingested
this writeup can reproduce the **default** instance from memory — that would be
contamination, not solving. The mitigation is structural: `ZSCTF_SEED` makes the
S-box, permutation, keys, multiplier, rotate, target and required key all
per-instance, so a memorised default (or a leaked solution for team A) yields
nothing for team B. The acceptance test proves divergence (different seed →
different target and different required key). What an agent *can* legitimately
carry across instances is the **logic shape** — which a human learns once too —
so per-instance variation forces genuine per-instance modelling (`system.html`
§9), not template recall. To also defeat shape-reuse, apply the §7
`PARAMETERISE`-the-shape variant.

**Human–AI differential.** This challenge does **not** claim a large
differential — it is a Hard crackme. The intended differential is small and
specific: (a) the no-gradient feedback penalises the breadth-first,
try-many-things agent style more than the patient human who builds a correct
mental model before running; (b) the modular-inverse / chain-direction /
scatter / computed-ROT traps are exactly the "looks obvious, is subtly wrong"
spots where fast pattern completion underperforms careful reasoning; (c) the
3.13-only, no-decompiler constraint removes a crutch. For a genuinely
AI-*resistant* version, apply the §7 extrapolations (per-instance logic-shape
shuffling, an algebra-gated layer, real packing/obfuscation, control flow),
which move the agent's cost up super-linearly while leaving the human's mental
model intact. We flag that honestly rather than overclaiming resistance from the
clean build.

## Interpreter requirement

Use Python 3.13. The participant artifact contains Python 3.13 bytecode. Python 3.12 can misinterpret the marshalled instructions and is not supported for this original artifact.
