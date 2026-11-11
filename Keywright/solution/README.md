# Keywright — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --image challenge/license.kwl --bin challenge/keywright
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Keywright — official writeup

**Flag:** `zerosecurectf{keywright_keygen_is_one_linear_solve}` (default seed; per-instance in production)

> Players receive only the stripped `keywright` engine and their `license.kwl`
> image. Everything below — the license format, the image layout, the constraint
> system and how to solve it — is what a solver *reconstructs*. It is written out
> here as the intended solution; none of it is handed to the player.


## 1. What you are looking at

`keywright` is an offline license-key validator. It:

1. loads the `.kwl` image (a dense constraint matrix `A`, a target vector `t`,
   and the XOR-wrapped flag),
2. reads your license key (one line), normalises it (uppercase, drops `-` and
   whitespace), and parses it into a vector of unsigned words `x`,
3. evaluates the constraint system `y = A·x` over the ring **Z/2³²** (32-bit
   unsigned arithmetic), and
4. accepts the key iff `y == t`. On acceptance it unwraps and prints the flag;
   otherwise it prints `DENIED`.

The whole difficulty is steps 3–4: recover the constraint system, then **solve
it** for the one key that satisfies every constraint at once.


## 2. The license format (recovered from the engine)

The key is `n` groups of `g` characters from a fixed Crockford-style base-32
alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I L O U`), joined by `-`. The
engine fixes `g = 6`; `n` comes from the image header. Each group decodes,
big-endian base-32, to one 32-bit word:

```
"YAEBXH" -> Y*32^5 + A*32^4 + E*32^3 + B*32^2 + X*32 + H  =  x[0]
```

So a 6-char group carries 30 bits, i.e. `x[i] ∈ [0, 2³⁰)`. Dashes and case are
cosmetic — the engine normalises them away before parsing.

### Image format (little-endian)

```
"KWL1" | u8 n | u8 g | u16 flag_len
u32 A[n*n]      (row-major constraint matrix, each entry mod 2^32)
u32 t[n]        (target vector)
u8  flag_ct[flag_len]
```

So `A` and `t` are in the image **in the clear**. What is *not* in the image is
the key, or the flag in plaintext (see §6).


## 3. The constraint system — the crux

The engine computes, for each row `i`,

```
y[i] = ( Σ_j  A[i][j] · x[j] )  mod 2^32
```

and checks `y == t`. That is a system of `n` **modular linear congruences**:

```
A · x  ≡  t   (mod 2^32)
```

`A` is **dense** (every `x[j]` appears in every equation) and **square**. The
generator builds `A` from generic 32-bit entries, rejection-sampled so that `A`
is invertible over GF(2) — equivalently, `det(A)` is **odd**, i.e. a unit modulo
2³². Over the ring Z/2³² a matrix is invertible iff its determinant is a unit, so

> `A` is invertible ⇒ `A·x ≡ t` has **exactly one** solution `x = A⁻¹·t`.

Exactly one solution vector ⇒ exactly one valid license key. (The acceptance
test asserts `det(A)` is odd and that the recovered `x` satisfies every
constraint.)


## 4. Why you cannot shortcut it

- **No brute force.** `n` is 5–7 words of 30 bits each, so the key space is
  `(2³⁰)ⁿ ≥ 2¹⁵⁰`. Hopeless.
- **No per-group attack.** `A` is dense, so every output word mixes *all* input
  words. You cannot solve one group at a time; the groups are entangled by the
  matrix. You must solve the system as a whole.
- **No `strings`, no patch, no known-plaintext** (see §6).

The intended path is therefore: recover `A`, `t`, the modulus and the parse, then
**solve the linear system**. That is one modular matrix inverse — milliseconds.


## 5. The one real subtlety — it is a *ring*, not a field

The arithmetic is modulo 2³², which is **not a field**: even numbers have no
multiplicative inverse mod 2³². This matters the moment you try to solve the
system.

- **Field-style Gaussian elimination can stall.** The textbook algorithm scales
  each pivot row by the inverse of the pivot. Over Z/2³² that step is invalid
  whenever the pivot is even. Because `A` is a *generic* unit matrix (not a tidy
  triangular form), a naive no-pivoting elimination hits an even, non-invertible
  pivot on **≈95% of instances** (measured: 57/60 seeds). The pivot has no
  inverse, so `pow(pivot, -1, 2**32)` raises and the solve dies — or, worse, a
  sloppy implementation "divides" with a wrong inverse and silently returns the
  wrong vector (→ `DENIED`, no crash to debug).
- **Solving over ℚ/ℝ is wrong.** Reducing the exact rational solution requires
  inverting its denominators *mod 2³²*; float arithmetic or rounding gives
  garbage.

The correct, always-valid routes:

1. **Modular matrix inverse.** `det(A)` is a unit, so the adjugate inverse
   `A⁻¹ = det(A)⁻¹ · adj(A)` exists mod 2³². Then `x = A⁻¹·t`. This is what
   `sympy.Matrix.inv_mod(2**32)` computes, and it is the reference solver's
   method.
2. **Pivot for units.** A Gaussian elimination that always chooses an *odd*
   (unit) pivot via row/column swaps works (one is always available because `A`
   is invertible mod 2).
3. **Smith normal form / 2-adic Hensel lifting** from mod 2 upward.

This ring-vs-field gap is the load-bearing "looks obvious, is subtly wrong" step.


## 6. The flag wrap — why you cannot cheat around the maths

The flag is stored as

```
flag_ct[i] = FLAG[i] XOR keystream(canonical_key)[i]
keystream(K) = SHA256(K || 0x00) || SHA256(K || 0x01) || ...   (truncated)
```

keyed on the **canonical form of the correct key** (`K` = the decoded words
re-encoded as uppercase, dashed groups). At run time the engine decodes your
key, re-encodes it canonically, and XORs `keystream(that)` into `flag_ct`.
Consequences:

- **`strings` / memory dumps reveal nothing.** The plaintext flag is never in the
  binary or the image. (The acceptance test asserts the flag and even the
  `zerosecurectf{` prefix are absent from the image bytes.)
- **Patching the comparison does not help.** If you NOP out the `y == t` check so
  the engine always prints, a wrong key still re-encodes to a wrong canonical
  string and derives `keystream(wrong_key)` — a hash of the wrong input — which
  unwraps `flag_ct` to garbage. We verified this directly: forcing the decrypt
  with a key that differs in a *single bit* yields random bytes, not the flag.
  Because `keystream` is a SHA-256 of the key, knowing a few flag bytes (the
  `zerosecurectf{` prefix) leaks nothing about `K` (preimage resistance), so
  there is no known-plaintext shortcut either.

The only path to the flag is the true key, and the only cheap way to the true key
is to solve the system.


## 7. Step-by-step

1. Reverse `keywright`: recover the `KWL1` image layout, the base-32 parse
   (`g=6`, the alphabet), that the check is `A·x == t` in **uint32** (so the
   modulus is 2³²), and the SHA-256 flag wrap keyed on the canonical key.
2. Parse `license.kwl`: pull `n`, `A` (n×n), `t`.
3. Solve `A·x ≡ t (mod 2³²)` with a **modular** inverse (not a field solve):
   `x = A.inv_mod(2³²) · t`. Sanity-check `A·x ≡ t`.
4. Re-encode `x` as the canonical key (6 base-32 chars per group, joined by `-`).
5. `printf '%s' "$KEY" | ./keywright license.kwl` → the flag.

The reference solver [`solution/solve.py`](solution/solve.py) does exactly this with
`sympy` and also drives the engine to print the flag:

```bash
python3 solution/solve.py --image license.kwl --bin ./keywright
```

Worked example (default seed `keywright-demo-seed`): a 6×6 system (227-byte
image); the solver recovers the key `YAEBXH-98A6GB-NE5HXR-3CKP2G-Z4J83A-S0322R`
and the engine returns the flag.


## 8. Design notes (for the ZSCTF team)

### Lineage (reconstruction, `corpus-genome.yaml` + `system.html` §17)

- **Seeds:** `zsctf-rev-018` *Flare Authenticator* (genome crux: "recover
  key-check logic from an obfuscated crackme"; scenario "software licensing /
  keygen"; affordances `[GROUND, PARAMETERISE, SUBSTITUTE-TARGET]`) is the primary
  donor — this is its "classic keygen scenario, per-instance key material"
  `reconstruct_idea` made concrete. `zsctf-rev-007` *revvm* (crux: "recover an
  unconventional … [embedded logic]") is a corroborating rev-reversing seed: here
  the thing to recover is not an ISA but a *constraint system*.
- **Operators applied** (`system.html` §17.3 operator set):
  - `GROUND` (acts on G9/G3): attach a real scenario — an offline license-key
    validator of the exact shape real products ship (keygen-checkable license
    keys verified by embedded arithmetic). Authenticity ↑↑, difficulty ≈0.
  - `SUBSTITUTE-TARGET` (G3): the abstract "obfuscated crackme" becomes a
    concrete, stripped native binary + a per-team data image the player actually
    runs. Self-containment preserved.
  - `SUBSTITUTE-PRIMITIVE` (G2/G1): realise the key-check as a **system of modular
    linear congruences over the ring Z/2³²**, so the crux is *"reverse the
    constraints, then SOLVE them"* (algebra), not *"invert a pipeline"* (which is
    the sibling challenge *Cogwork*'s crux). This is what distinguishes Keywright
    from Cogwork.
  - `GUARD-SWAP` (G6): replace obscurity with a **real mitigation** — a
    SHA-256-keyed flag wrap that defeats `strings` and binary patching.
  - `PARAMETERISE` (any knob): expose `ZSCTF_SEED` so `n`, the key, the matrix
    `A`, the target `t` and the flag wrapping are all per-instance.
- **Crux (load-bearing):** recognising the embedded data as a dense modular
  linear system over a *ring*, and solving it correctly (modular inverse, not a
  field solve). Trivialise it (hand over `A⁻¹`, or make `A` triangular) and the
  challenge collapses — confirming it is load-bearing (§17.2).
- **Honest difficulty band: Hard.** The maths is first-year linear algebra and
  the system is clean and unobfuscated; a competent reverser with the binary gets
  the format and the matrix, and one modular solve finishes it. The single real
  spike is the ring-vs-field pivot trap (§5). We do **not** inflate this to
  Extreme. (By the same honest standard, the sibling *Cogwork* is also Hard.)

### Harder variants (extrapolation, tracked but not built here)

- `SUBSTITUTE-PRIMITIVE` → a **small nonlinear system**: add quadratic constraints
  (`x_i·x_j` terms) that still pin a unique root, so the solve needs a Gröbner
  basis / resultants over the ring rather than one inverse. → toward Extreme.
- `SUBSTITUTE-PRIMITIVE` → a **CRC / checksum lattice**: replace the matrix with a
  GF(2)-linear bit system (parity/CRC constraints), solved by linear algebra over
  GF(2). Same "solve the system" shape, different algebra.
- `PARAMETERISE` the modulus: mix several coprime moduli and glue with CRT, or use
  a prime field *and* a 2-power ring in one instance, so the solver must detect
  the ring per block.
- `CONCEAL-SHIFT` / `GUARD-SWAP`: obfuscate the parse / matrix load (opaque
  predicates, a tiny VM around the matrix-multiply, anti-debug) so recovering the
  system is itself work. → toward Frontier.
- `CHAIN` (X): feed the recovered key into a second stage (it decrypts a payload),
  the rev+crypto shape of the §17.5 example.


## 9. RED-TEAM / AI-RESISTANCE

**How a capable AI agent would attack this.** With tools (a shell, a
disassembler, Python+sympy) an agent's realistic pipeline is: `file`/`strings`
the binary; disassemble it; spot the SHA-256 constants and a nested-loop
multiply-accumulate; recognise the `KWL1` container and a base-32 parse; identify
the check as `A·x == t` in uint32; parse the image; then solve the system. **An
agent that gets that far will solve it** — the final step is a one-line
`A.inv_mod(2**32) * t`. We state this plainly; this is a Hard challenge, not an
AI-proof one.

**Where an agent actually slips.** The resistance is real but *narrow*:

1. **Ring vs field (the big one).** The arithmetic is mod 2³², not a prime field.
   An agent that reaches for a prime-field linear solver, solves over ℚ and
   rounds, or runs Gaussian elimination without unit-pivoting hits an even,
   non-invertible pivot on **≈95% of instances** (measured 57/60). `pow(even, -1,
   2**32)` raises; a hand-rolled inverse returns garbage. The fix (modular inverse
   because `det` is a unit, or pivot-for-odd) is "obvious in hindsight" — exactly
   the spot where fast pattern-completion underperforms careful reasoning.
2. **Parse details.** 30 bits per 6-char group (not 32); a Crockford alphabet with
   `I L O U` removed and `0/O`, `1/I` *not* interchanged in the strict decoder;
   big-endian digit order; the keystream keyed on the **canonical re-encoding**,
   not the raw typed bytes. Any of these wrong → a right-looking vector that still
   fails, or a correct vector that unwraps the flag to garbage.
3. **Endianness / framing.** `A` and `t` are little-endian u32; `n` from the
   header; off-by-one in the container offsets corrupts the matrix silently.

As with the sibling *Cogwork*, the SHA-256 flag wrap (§6) means there is **no
partial-credit signal** — a key that is one bit wrong unwraps to pure garbage,
exactly like a key that is entirely wrong. An agent cannot hill-climb; it must get
the whole model right before it sees anything but `DENIED`. That removes the
feedback loop breadth-first agents lean on.

**Is the resistance real, or just annoyance?** Honestly: it is *modest*. The
ring-vs-field trap is a genuine, measurable stumble (95% of instances break a
naive solve), but it is one idea, and a careful agent clears it. The durable
protection is the next point.

**Contamination note.** The format, the modulus, the parse and the default-seed
key/flag above are now written down. An agent that has ingested this writeup can
reproduce the **default** instance from memory — that would be contamination, not
solving. The mitigation is structural: `ZSCTF_SEED` makes `n`, `A`, `t`, the key
and the flag wrapping all per-instance, so a memorised default (or a leaked
solution for team A) yields nothing for team B. The acceptance test proves
divergence (different seed → different target and different required key). What an
agent *can* legitimately carry across instances is the *method* — which a human
learns once too — so per-instance variation forces genuine per-instance solving
(`system.html` §9), not template recall.

**Human–AI differential.** This challenge does **not** claim a large differential;
it is a Hard crackme and strong humans and strong agents both finish it. The
intended differential is small and specific: (a) the no-gradient feedback
penalises the try-many-things agent style more than the patient human who builds a
correct mental model first; (b) the ring-vs-field pivot trap is precisely the
"looks like a field, isn't" spot where fast pattern completion picks the wrong
algorithm. For a genuinely AI-*resistant* version, apply the §8 extrapolations (a
nonlinear/Gröbner system, mixed moduli with CRT, an obfuscated matrix load), which
raise the agent's cost super-linearly while leaving the human's mental model
intact. We flag that honestly rather than overclaiming resistance from the clean
build.
