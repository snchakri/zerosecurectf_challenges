# Direct Syscall Invocation & API Hashing — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Direct Syscall Invocation & API Hashing (rev_02)


## Flag
`zerosecure{direct_system_call_djb2_hashing_47ba}`


## Design summary
`dist/rev02_syscalls` embodies two bits of real tradecraft: it writes its output
through an inline `syscall` stub (bypassing the libc wrapper, the classic
"unhooked syscall" technique) and it derives its keystream from DJB2 hashes of API
names (only the hashes are embedded, never the names). The parameter+target blob is
located by the magic `D2SYSAPI`:

```
off 0  MAGIC    8  "D2SYSAPI"
off 8  N        u16   flag length (48)
off 10 STATE0   u32   keystream state seed (0x811C9DC5)
off 14 SEEDS[8] u32x8 DJB2 hashes of API names
off 46 TARGET[N]
```

Forward transform, `state = STATE0`:
```
s = SEEDS[i % 8]
m = s ^ rotl32(state, (i & 7) + 1)
h = djb2_over_4_bytes_LE(m)          # h=5381; h = h*33 + byte
k = (h ^ (h>>16) ^ (h>>24)) & 0xFF
out[i] = (i & 1) ? (in[i] ^ k) : ((in[i] + k) & 0xFF)
state  = state*33 + out[i]           # mod 2^32
```
Accept iff `out == TARGET`.


## Why it is not trivially broken
`strings` yields nothing (confirmed) -- no plain/hex/base64/reversed flag. The
seeds look like opaque constants; recognising them as DJB2 API hashes and
reconstructing the exact keystream mixing (seed selection, rotate amount, the inner
DJB2 over the mixed word, the fold, and the parity-dependent op) is the work. The
direct-syscall output path also removes the obvious import to hook.


## Intended solution
`state` evolves from the produced byte `out[i]`, which equals `TARGET[i]`, so the
keystream is fully determined by the embedded blob:

1. Read `N`, `STATE0`, the eight seeds, and `TARGET`.
2. For each `i`, recompute `k` from `state` and `SEEDS[i%8]`.
3. Invert: `in[i] = (i&1) ? TARGET[i]^k : (TARGET[i]-k)&0xFF`.
4. Advance `state = state*33 + TARGET[i]`.

O(N), no brute force. `solve.py` parses the ELF and prints the flag.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{direct_system_call_djb2_hashing_47ba}
```


## Rebuild
```
wsl -d Ubuntu -- bash src/build.sh
```
`src/gen.py` recomputes the DJB2 seeds and the transformed target from the `flag`
file and emits `src/blob.h`; the flag string itself is never written.
