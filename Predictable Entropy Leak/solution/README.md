# Predictable Entropy Leak — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Predictable Entropy Leak (MT19937 State Recovery)


## 1. Analysis & Theoretical Foundations
MT19937 is a linear generator with 19937 bits of internal state, held as
`N = 624` 32-bit words. Each call to `getrandbits(32)` returns one state word
passed through a fixed, bijective **tempering** function:

```
y  = x
y ^= y >> 11
y ^= (y << 7)  & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```

Because every step is invertible, observing 624 consecutive outputs is exactly
enough to recover the full internal state — and therefore to predict every
future output. The seed is irrelevant: the attack works on the *state*, not the
key schedule.


## 2. Why the handout is solvable (and only this way)
`prng_stream.txt` contains precisely 624 consecutive outputs. `generator.py`
documents that the admin vault was sealed by XORing it with the keystream formed
from the **subsequent** outputs (4 big-endian bytes per 32-bit word). The flag
never appears in any artifact; `sealed_vault.hex` is pseudorandom until the
keystream is reconstructed, so `strings`/grep and every plain/hex/base64/reversed
encoding reveal nothing.


## 3. Step-by-Step Walkthrough
1. **Untemper.** Invert the four tempering steps *in reverse order*. The two
   right-shifts (`>>18`, `>>11`) and the two masked left-shifts (`<<7`, `<<15`)
   each invert by iterating the XOR until the recovered bits stabilise (3 passes
   for a shift of 11, 5 passes for a shift of 7 is more than sufficient).
2. **Clone.** Place the 624 recovered words into a fresh generator with the
   index set to 624 (`random.Random().setstate((3, tuple(words + [624]), None))`)
   so the next draw triggers the twist — reproducing the exact outputs that
   followed the captured run.
3. **Replay & unseal.** Draw `ceil(len(vault)/4)` words, serialise each as four
   big-endian bytes, truncate to the vault length, and XOR over
   `sealed_vault.hex`.

The XOR output is the flag.


## 4. Why it resists shortcuts
- There is no brute force: the state is recovered algebraically in O(N).
- The seed is never used, so guessing or grinding the seed is a dead end.
- The vault bytes are indistinguishable from random without the clone.


## 5. Solver & Verification
`solve.py` reads only `dist/prng_stream.txt` and `dist/sealed_vault.hex`:
```bash
python solve.py --dist ./dist
```
Output is the recovered `zerosecure{...}` flag, byte-identical to `flag`.


## 6. Citations & References
- Matsumoto, M. & Nishimura, T. (1998). *Mersenne Twister: A 623-dimensionally
  equidistributed uniform pseudo-random number generator.* ACM TOMACS 8(1).
- CPython `Modules/_randommodule.c` — `genrand_uint32`, `init_by_array`,
  `random_setstate` (the tempering constants and 624-word state layout).


## 7. Defense Engineering & Remediation
Never use a general-purpose PRNG for anything security-relevant. Nonces, tokens
and keystreams must come from a CSPRNG (`secrets`, `os.urandom`, or an AEAD's
own nonce discipline). MT19937's output is fully predictable from a window of
its outputs; its only legitimate use is simulation and non-adversarial sampling.
