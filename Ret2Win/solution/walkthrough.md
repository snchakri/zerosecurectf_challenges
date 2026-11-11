# RET2WIN DECOY — author walkthrough

Overflow `buf[64]` in `vuln()` via `read(0, buf, 0x100)`.

- Offset to saved return address: **72** (64 + 8 saved rbp).
- Add a `ret` gadget before the target for 16-byte stack alignment (`puts`).

| Path | Jump to | Prints | Verdict |
|------|---------|--------|---------|
| bait | `win()` | `DOOM{r3t2w1n_t00_0bv10us}` | decoy |
| earned-fake | `admin()` | `DOOM{s3cr3t_4dm1n_pwn3d}` | decoy |
| **egg** | *don't exploit* — clean exit calls `goodbye()` | `control flow redirected into an empty room. no occupants, no flags.` | the only true endpoint |

The cruelty: the real message only appears when you **don't** pop the stack.

Run `python3 solve.py` (needs pwntools + the shipped libc/ld).
