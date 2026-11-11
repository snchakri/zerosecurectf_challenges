# Revenant — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Revenant — official writeup

**Category:** pwn (heap) · **Honest difficulty band:** **Medium** (re-banded down from Hard — see below).
**CWE:** CWE-416 (use-after-free), CWE-824 (access of uninitialized/dangling pointer).

A self-contained teaching binary. The exploit is a use-after-free that
overwrites a heap struct's function pointer and redirects it to a `win()`
routine in the same image. It is a technique against *this toy binary only*; it
relies on mitigations (PIE, CET) being switched off at compile time so the
mechanics are visible.

---


## The mechanism

Each record is:

```c
typedef struct record {
    char     label[16];                  /* 0..15  */
    uint64_t checksum;                   /* 16..23 : inert                    */
    void   (*render)(struct record *);   /* 24..31 : handler (hijack target)  */
} record_t;                              /* sizeof == 32 -> malloc gives 0x30  */
```

Four facts combine into the bug:

1. **`rename` is bounded to the label.** A live record can only ever have its
   first 16 bytes rewritten, so `render` (offset 24) is unreachable the honest
   way. This is what forces the UAF — you cannot just overwrite the pointer.
2. **`free` dangles the slot.** `cmd_free()` calls `free(slots[id])` but does
   **not** clear `slots[id]` or its kind (the classic missing `= NULL`). The
   slot keeps pointing at a now-freed chunk (CWE-416).
3. **tcache same-size reuse is deterministic.** `sizeof(record_t)==32` →
   `malloc(32)` returns a chunk in the `0x30` tcache bin. After `free`, a
   `note` whose request also falls in the `0x30` bin (request ≥ 25 bytes) is
   handed back that exact chunk. In a single-threaded process this LIFO reuse
   is guaranteed — no race, no metadata forgery.
4. **A note's whole buffer is writable.** `write` on a note is bounded only by
   the note's own size, so writing 24 padding bytes + an 8-byte address reaches
   the overlapping `render` field of the dangling record.

`win()` reads `ZSCTF_FLAG` from the environment and prints it. It is never
installed as a handler on the benign path, and `-no-pie` fixes its address.

### The intended path

```
new            # record #0  -> 0x30 chunk, render = default_render
free 0         # chunk -> 0x30 tcache; slot 0 dangles (UAF)
note 32        # note #1 reuses chunk 0; its buffer overlaps record #0
               #   (creating the note zeroes the buffer, so render becomes 0)
write 1 32     # 24 pad bytes + p64(&win)  -> sets record#0.render = win
<raw 32 bytes>
render 0       # dangling record #0 invokes render == win  -> flag
```

No leak: `&win` comes from the binary's symbol table (`nm ./revenant | grep ' win$'`),
which every team has because the exact deployed binary is handed out.

---


## Offset / size-class derivation 

- `offsetof(record_t, render) == 24` and `sizeof(record_t) == 32` are enforced
  at compile time by `_Static_assert` in the source, so the "offset 24, pad 24"
  figure is not guessed — it is read off the struct.
- glibc chunk sizing: `malloc(n)` uses a usable size rounded so that the total
  chunk (incl. the 8-byte header) is 16-aligned. `n` in `25..40` → `0x30`
  chunk; `n ≤ 24` → `0x20` chunk. Hence a note must request ≥ 25 bytes to
  collide with a record; the solver uses 32. (Reference: glibc malloc
  `request2size`, and the tcache design note in
  <https://sourceware.org/glibc/wiki/MallocInternals>.)
- tcache LIFO reuse: `tcache_get`/`tcache_put` in glibc `malloc/malloc.c` pop
  the most recently freed same-size chunk first; single-threaded, this is fully
  deterministic.

Verified `win()` address in the reference gcc-13 `-no-pie` build: `0x401654`
(the solver resolves it dynamically, so a different toolchain placing it
elsewhere still solves).

---


## Why **Medium** (honest banding; re-banded down from Hard)

Per `CLAUDE.md` (no inflation; reproducibility over flashiness) and a red-team
review that flagged the original **Hard** label as inflated: the source is
handed to the player and the UAF -> function-pointer-hijack primitive is a
well-known class a capable solver or LLM recognises quickly, so discovery is
cheap. The honest band is **Medium** — real work remains in the *execution*,
not the *recognition*.

- **Why still Medium, not Easy:** it requires recognising a UAF, reasoning about
  the struct layout (pointer at offset 24, not 0), and matching the tcache size
  class so the note overlaps the record. Benign use cannot win; three distinct
  near-misses (below) fail. An unaided solver must assemble a multi-step heap
  interaction, not run one tool — more than an on-ramp, but with the bug class
  in plain source it does not reach Hard.
- **Deliberately not Extreme (and not Hard):** a true Extreme heap challenge would add ASLR +
  an info-leak primitive and a *metadata* attack (tcache/fastbin poisoning,
  defeating safe-linking, forging chunk sizes). We **chose not to**, because
  those are glibc-version-fragile and would make the challenge non-reproducible
  across the dev host (glibc 2.39) and the deploy image (glibc 2.36). This
  variant corrupts **no** allocator metadata and needs **no** leak, so it
  reproduces byte-for-byte in behaviour on both. Reproducibility beats
  flashiness — stated plainly, as the brief requires.

---


## Mitigation / glibc posture

- Build flags: `-O0 -fno-stack-protector -no-pie -fcf-protection=none`.
  `-no-pie` (fixed `win()` address, no leak needed) and `-fcf-protection=none`
  (indirect call to `win()` allowed) are the deliberate teaching choices; the
  stack canary is irrelevant to a heap UAF and is dropped only to keep the
  disassembly clean.
- glibc: dev/test Ubuntu 24.04 **2.39**; deploy image Debian 12 bookworm
  **2.36**. The technique is metadata-free, so it is stable across glibc ≥ 2.26
  (tcache era).
- Deployment hardening (compose): non-root uid 10001, read-only root FS,
  `tmpfs /tmp`, `cap_drop: ALL`, `no-new-privileges`, internal (no-egress)
  network, pids/mem/cpu limits. The flag is only ever in the process
  environment — never on disk, never in an image layer.

---


## Rabbit-holes 

Per `HARDENING.md`: every trap is **escapable by reasoning** (guess-exposure 0),
varies per instance where noted, and is a real artifact, not cosmetic text.

| # | Operator | Trap | The reasoning-based tell that rejects it |
|---|----------|------|------------------------------------------|
| RH1 | R1 (decoy flag) | Banner line `zerosecureCTF{LEGACY_BUILD_TAG_IGNORE}` — the first flag-shaped hit a `strings`/`grep -i` surfaces. | Fails the **published** validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$`: uppercase `CTF`/body. Rejectable on sight. |
| RH2 | R5 (per-instance decoy) | Banner line `zerosecurectf{SESS-<hash>}`, where `<hash>` is FNV-1a over `ZSCTF_SEED` — so it differs per team and a leaked walkthrough's value does not transfer. It is the **first** `zerosecurectf{` match in the output, so a naive "grab the first match" returns it. | Fails the validator: the `-` and uppercase `SESS` are outside `[a-z0-9_]`. The reference solver's `extract_flag()` only accepts the first match that passes the validator — documenting the escape. |
| RH3 | R4 + R2 (inert symbol / footgun) | `admin_panel()` has external linkage and sits right next to `win()` in `nm`, and the `promote` command invokes it. It *looks* like the escalation path. | Reading the source shows `admin_panel()` reads **no** environment and prints "sealed … no archival token". Only `win()` calls `getenv("ZSCTF_FLAG")`. Redirecting the handler there yields a taunt, not the flag. |
| RH4 | R3 (representation / near-miss) | Two tempting-but-wrong layouts: (a) a `note` of ≤ 24 bytes (lands in the `0x20` bin, never overlaps the `0x30` record → `render` stays default, benign "idle"); (b) writing 16 bytes to hit `checksum` instead of 24 to hit `render` (→ `render` stays 0 from the note's zeroing → crash, no flag). | Rejectable by the two derivations above: the size class comes from `request2size` (≥ 25 → `0x30`), and the offset comes from `offsetof(record_t, render) == 24`, both fixed in the source. A careful solver computes them; a careless one loops on a corrupt-but-not-winning state. |

`benign use does not win`, `wrong size class does not win`, `wrong offset does
not win`, `admin_panel discloses no flag`, `both decoys fail the strict
validator`, `the lazy first-match shortcut returns a decoy`, and `the strict
extractor returns exactly the real flag`.

---


## Unintended-path scan (red-team)

- **Win without the UAF?** No. `rename` is capped at the 16-byte label; `write`
  only accepts a note id; `render` only accepts a record id. The only way to
  put a non-default pointer into `render` is to overlap a freed record with a
  note — the intended primitive. Confirmed by the "benign use" check.
- **`promote`/`admin_panel`?** Inert; reads no environment (RH3). Confirmed.
- **Leak the flag from memory via `show`?** `show` prints only `label` (≤ 15
  bytes) and the inert `checksum`; neither ever holds the flag. `win()` is the
  sole reader of `ZSCTF_FLAG`.
- **Double-free / tcache key abuse?** Freeing twice trips glibc's tcache
  double-free detection and aborts — a dead-end crash, not a win. Not on any
  path to the flag.
- **Flag in the binary / an image layer?** No. Only the clearly-marked
  `zerosecurectf{REPLACE_ME_AT_DEPLOY}` placeholder and the inert
  `zerosecurectf{SESS-` decoy *fragment* are embedded; the configured flag is
  injected via `ZSCTF_FLAG` at run time and asserted absent from the binary.
- **Determinism:** same source + flags + toolchain → byte-identical binary
  (asserted); same `ZSCTF_SEED` → identical decoy, different seed → different
  (asserted). We assert source-level / same-toolchain determinism only; we do
  **not** claim cross-toolchain binary byte-identity (hence the symbol-table
  resolution in the solver).

---


## One-command reproduction

```bash
ZSCTF_FLAG='zerosecurectf{us3_aft3r_fr33_handler_hijack_wins}' \
ZSCTF_SEED='team-alpha-0007' \
```

## Local binary

The event backup omitted the downloadable binary. `challenge/revenant` is a Linux x86-64 rebuild from the archived challenge source. It uses the same documented build flags; it is not claimed to be byte-identical to the event host.

```bash
python solution/solve.py --local challenge/revenant
```
