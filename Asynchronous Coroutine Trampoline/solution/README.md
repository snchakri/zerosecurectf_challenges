# Asynchronous Coroutine Trampoline — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Asynchronous Coroutine Trampoline (Generator State Machine)


## 1. Analysis & Theoretical Foundations
The handout `dist/checker.pyc` is a CPython 3.13 module implementing a
cooperative coroutine *trampoline*. Three generator "workers" are primed with
`next()`, and a central `trampoline(data)` loop dispatches one input byte at a
time to the worker selected by `i % 3` via `worker.send((byte, state))`. The
value yielded back is salted and appended to an output buffer; a running 32-bit
`state` word is then advanced. The module accepts a candidate iff
`trampoline(candidate) == TARGET`, where `TARGET` is an embedded opaque blob.
No plaintext key is present in the bytecode.


## 2. The transform (recovered from the bytecode)
Let `SALT` (16 bytes), `SEED`, `MULT = 0x01000193` (FNV prime),
`ADD = 0x9E3779B1` be the constants found in `co_consts`. For input byte `b` at
index `i`, with `r = i % 3`:

- `r == 0` (worker_xor): `x0 = b XOR (state & 0xff)`
- `r == 1` (worker_add): `x0 = (b + ((state >> 5) & 0xff)) & 0xff`
- `r == 2` (worker_rot): `x0 = rotl8(b, (state % 7) + 1)`

Then `x = x0 XOR SALT[i % 16]`, `out[i] = x`, and the feedback update is:

```
state = (state * MULT + x + ADD) & 0xffffffff
```

Crucially the update consumes the **output** byte `x`, which is exactly the byte
stored in `TARGET`. This makes the whole pipeline invertible in a single
left-to-right pass with no search.


## 3. Step-by-Step Walkthrough
1. Load the `.pyc`: strip the 16-byte header and `marshal.loads` the body to get
   the module code object; recurse through `co_consts` to collect constants.
2. Identify `SALT` (the 16-byte blob), `TARGET` (the long blob = key length),
   and the scalar constants `SEED`, `MULT`, `ADD`.
3. Replay the state forward while inverting each worker:
   - set `state = SEED`
   - for each `x = TARGET[i]`: `x0 = x XOR SALT[i%16]`; invert the worker op for
     `r = i%3` (XOR back, subtract, or `rotr8`) to get `b`; emit `b`; then
     advance `state = (state*MULT + x + ADD) & 0xffffffff`.
4. The emitted bytes are the flag.


## 4. Why it resists shortcuts
- `strings` / grep reveal nothing: only a scrambled `TARGET` blob is stored.
- A one-shot guess fails because the control flow is carried by `send`/`yield`
  scheduling and a per-byte feedback state; you must model the scheduler and the
  state recurrence to invert it. It is not a single global XOR.
- It is nonetheless fully deterministic — recovery is O(n), no brute force.


## 5. Exploit Script & Verification
`solve.py` reads only `dist/checker.pyc`, extracts the constants, and inverts
the pipeline:
```bash
python solve.py --dist ./dist
```
Output: the recovered `zerosecure{...}` key, byte-identical to the `flag` file.


## 6. Citations & References
- Beazley, D. (2009). *A Curious Course on Coroutines and Concurrency.*
- Python Software Foundation. *PEP 342 — Coroutines via Enhanced Generators.*
- Fowler, G., Noll, L. C., Vo, K.-P. *FNV hash* (origin of `0x01000193`).


## 7. Defense Engineering & Remediation
Obfuscation via coroutine scheduling is only reverse-engineering friction, not a
cryptographic control. Gate secrets behind authenticated key exchange and a KDF;
never embed a key (or a trivially invertible encoding of one) in client code.
