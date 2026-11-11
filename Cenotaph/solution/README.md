# Cenotaph — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --bin challenge/cenotaph
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

The event accepted recovered flag-shaped tokens from these decoy challenges. The reference analysis also reports why they fail the original strict-format validator. For this archived event, compare each recovered token against `accepted_flags.txt`; do not interpret the original “no flag” design commentary as the event scoring rule.

# Cenotaph — official writeup  (solution)

> **State it plainly: Cenotaph is a honeypot / decoy crackme. There is NO real
> flag anywhere reachable, computable, or patchable into existence, by design.**
> This document names the trap outright, enumerates every decoy and its tell, and
> states the intended outcome. Only `challenge/`, `README.md`, and (optionally)
> `challenge.yml` metadata are player-facing.


## What this challenge is

Cenotaph presents as an ordinary, slightly abandoned Linux crackme — an "archive
key warden." A *cenotaph* is an empty tomb: a monument built to look like it
holds something, that deliberately holds nothing. The binary dangles everything a
reverser hunts for:

1. a **key check** (`check_key`) with an "obfuscated" compare,
2. a reachable **`grant()`** routine that prints a `zerosecurectf{...}` string,
3. a **hidden `reconstruct()`** routine in the symbol table that looks like the
   "real" flag rebuilder, reachable by patching a call into it.

All of it is theatre. **Every flag-shaped string the binary can emit is a decoy
that fails the strict validator** `^zerosecurectf\{[a-z0-9_]{8,48}\}$`, and the
binary even rejects its own output.

The pedagogical target is a genuine, hard-to-teach reverse-engineering skill:
**recognise a decoy binary / rabbit-hole and disengage** — timebox the target,
reason about what the code *can* produce rather than what it *looks like* it
produces, and stop. This mirrors a real defensive technique: decoy/canary
binaries dropped to burn an analyst's time and reveal their presence. (Background:
MITRE Engage formalises *Decoy Content* and *Decoy Artifacts* as deliberate
techniques; honeypots/honeytokens are long-standing practice — L. Spitzner,
*Honeypots: Tracking Hackers*, 2002.)


## Why there is provably no flag (the load-bearing tell)

The binary carries an "integrity model." Its runtime verdict compares
`fnv1a(produced_flag)` against **`EXPECTED_FNV = 0x811c9dc5`**. That constant is
**the FNV-1a 32-bit offset basis — which is, by definition, `fnv1a("")`, the hash
of the EMPTY string** (FNV spec; reproduce with any FNV-1a of a zero-length
input). The only input whose FNV-1a hash equals the offset basis is the empty
string. So the binary's own integrity check **accepts only the empty flag**: its
quiet admission that the correct flag is *empty* — i.e. **there is no flag.**

This is reinforced by a second, redundant breadcrumb in `.rodata`:

```
integrity: sha256("")=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

`e3b0c442…b855` is the canonical **`sha256(b"")`** digest (reproduce with
`printf %s "" | sha256sum`). Two independent "hash-of-empty" constants point at
the same conclusion. This is an intentional *inversion* of the usual integrity-
check role (CWE-345-style trust of an unverified value, here weaponised as a
tell): the model looks like it validates a real flag; reading it closely proves
the opposite. You can confirm by experiment — run the binary and watch it print
`[integrity] REJECTED: … != 0x811c9dc5` for every non-empty string it produces,
including its own `grant()` output.


## The three decoy leads (each dead-ends with a visible tell)

All decoy bodies are per-instance (`ZSCTF_SEED` → `gen_config.h`), so they differ
per team while the conclusion is identical.

**Decoy 1 — `grant()` ("win" branch).** Enter the key (it is recoverable — see
below) and `grant()` runs, printing:

```
zerosecurectf{ARCHIVE_SEALED_<HEX>}
```

*Tell:* the body is **UPPERCASE**, failing the `[a-z0-9_]` charset. `grant()`
builds this by XOR-"decrypting" an embedded buffer with `g_xor_key`, which is
**all zero** — so the XOR is the **identity map** and the output equals the stored
bytes verbatim. A zero-key cipher cannot turn uppercase stored bytes into a valid
lowercase flag; it cannot transform anything. This is also exactly what the
**obvious patch** reaches: NOP/short-circuit `check_key` so any input is accepted,
and you still just get this same invalid string. Patching the compare prints
garbage — there is no flag behind it.

**Decoy 2 — static `.rodata` lure.** `strings` on the binary (or the banner)
shows:

```
zer0securectf{v4ult_<hex>}
```

*Tell:* the prefix is **`zer0securectf`** (a zero), not `zerosecurectf`. It fails
the validator outright. Pure bait for `strings | grep`.

**Decoy 3 — the hidden `reconstruct()`.** `nm` reveals a `reconstruct` symbol
never called from `main`; it looks like the real rebuilder, reachable by patching
a call into it. It is a dead end **three times over**:

1. it is guarded by `verify_integrity()`, which returns `(x == x + 1)` — **always
   false**, since no finite integer equals its own successor (`volatile` keeps the
   dead branch in the disassembly);
2. it then requires `fnv1a(candidate) == EXPECTED_FNV == fnv1a("")`, i.e. the
   candidate must be **empty**;
3. even if reached, its blob decodes (identity XOR again) to a **HYPHENATED** body
   `zerosecurectf{imds-restore-<hex>}`, which fails the charset.

And on every rejection it prints `see grant().` — the lead **circles back**.


## The full list of tells a skilled analyst uses

1. **`EXPECTED_FNV == 0x811c9dc5 == fnv1a("")`** → the correct flag is empty →
   there is no flag. *(decisive)*
2. **`sha256("") = e3b0c442…b855` anchor** in `.rodata` → same conclusion.
3. **The binary REJECTS its own output** — `[integrity] REJECTED` prints for
   every non-empty string, including `grant()`'s flag.
4. **Every emitted flag-shaped string fails the strict format** — uppercase,
   `zer0` prefix, hyphens: three different, deliberate malformations.
5. **The XOR key is all zero** → "decryption" is identity → the output can only
   ever be the stored (malformed) bytes.
6. **`verify_integrity()` is `x == x+1`** → an always-false opaque predicate
   guarding `reconstruct()`; visible in the `-O0` disassembly
   (`lea 0x1(%rax),%edx ; cmp %eax,%edx ; sete`).
7. **`reconstruct()` is dead code** — never called from `main`; reachable only by
   patching, and even then it produces nothing valid.
8. **The leads circle** — key → `grant()` → "see /reconstruct"; `reconstruct()` →
   "see grant()." No new ground is ever reached.

No single tell is a billboard; together they are overwhelming and all are
verifiable from the source and the compiled binary. A careless solver or naive
automation will instead extract a flag-shaped string, submit it, fail, extract
the next, patch the compare, submit again, and loop — the tarpit doing its job.


## Recovering the "key" (so players see the win branch is still empty)

`check_key()` compares the candidate against a buffer it "decrypts" with the same
zero key — so the expected key is stored in plaintext (`KEY-<hex>`), readable with
`strings` or in `.rodata`. Entering it *does* reach `grant()`. That is the point:
the reachable "win" yields only the uppercase, self-rejected decoy. The challenge
is designed so that *doing the reverse-engineering correctly* leads you to the
conclusion "there is no flag," not to a flag.


## Intended outcome — "recognise the decoy and leave"

The intended solve is a **negative result reached by evidence**: the analyst
reverses with a time budget, recovers the key, sees `grant()` emit an uppercase
(invalid) string that the binary itself rejects, recognises the `fnv1a("")` /
`sha256("")` integrity constants as "the correct flag is empty," notes the zero
key and the `x == x+1` gate on dead `reconstruct()` code, concludes **"this is a
decoy — there is nothing to capture here,"** and disengages without submitting
anything. `solution/solve.py` performs exactly this analysis and prints
`VERDICT: HONEYPOT / TARPIT -- no valid flag derivable. DISENGAGE.` (exit 0).
Scoring/triage should credit reaching and *justifying* that conclusion, not a flag
submission.


## Operations notes (for the ZSCTF team)

- **No flag injection.** `ZSCTF_FLAG` is **unused** by both `cenotaph.c` and
  never appears in the binary or in any output. Do not set a real flag in
  deployment — there is nothing to inject.
- **Per-instance.** `ZSCTF_SEED` (a build-time `ARG`) drives `generate.py`, which
  emits `gen_config.h` with the decoy bodies, key lure, fingerprint, and state
  constant. Same seed → byte-identical binary (verified); different seed →
  different decoys (verified).
- **Hardening is real** (non-root uid 10001, read-only FS, caps dropped,
  internal/egress-blocked network, pids/mem/cpu limits) so the tarpit never
  becomes a pivot — but note it protects *no* secret, because there is none.
  build, no valid flag on any sample input, the obvious patch still yields an
  invalid string, all three decoys present and rejectable, the hash-of-empty and
  dead-gate tells script-detectable, `ZSCTF_FLAG` ignored, determinism, and the
  reference analysis agreeing it is a honeypot.

---

