# Matryoshka — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Matryoshka — official writeup

**Flag:** `zerosecurectf{p33l_th3_hex_b4s3_and_cl4ss1c4l_l4y3rs}` (static demo
seed; per-instance in production)

**Band:** Easy (honest). Every layer is a standard, self-identifying transform;
the only "attack" is recognising alphabets and a 25-way brute force of a Caesar
shift. No modern crypto, no keys, no tooling beyond the standard library.


## The wrapping

The service builds an envelope around the flag and wraps it (outermost last):

```
message = "ZSCTF intercept session=<tag> :: <flag>"
  -> Caesar shift by K   (letters only; K = 1..25, per-instance)
  -> Atbash              (letters only, a<->z ...)
  -> Base32 encode
  -> Base64 encode
  -> Hex encode
```


## Peeling it (the decision path)

Each encoding layer gives itself away by its character set, so you always know
what to do next:

1. **Hex** — the blob is lowercase `0-9a-f` and even length → `bytes.fromhex`.
2. **Base64** — the result is `A-Za-z0-9+/` with `=` padding and length a
   multiple of 4 → `base64.b64decode`.
3. **Base32** — that result is uppercase `A-Z2-7` with `=` padding and length a
   multiple of 8 → `base64.b32decode`.
4. **Classical** — now you have ordinary text with spaces and punctuation (no
   longer a recognised encoding alphabet). It is Atbash ∘ Caesar. Undo **Atbash**
   (it is its own inverse), then try all **25 Caesar shifts** and keep the one
   that produces the flag format `zerosecurectf{...}`.

```bash
python3 solution/solve.py --file challenge/ciphertext.txt
# [*] peeled encoding layers (outer->inner): hex -> base64 -> base32
# [*] Caesar shift was K = ...; recovered envelope: 'ZSCTF intercept session=... :: zerosecurectf{...}'
# [+] FLAG = zerosecurectf{...}
```

The reference solver auto-detects each layer rather than hard-coding the order,
so it would peel any nesting of hex/base32/base64 it is handed, then resolve the
classical layer by the 25-way search.


## Integrity / why the shortcuts do not work

* **No plaintext flag.** The flag only exists after all five layers are undone;
* **The full path is required.** Stopping one layer short leaves base64/base32
  text, not the flag; and only the single correct Caesar shift reveals the flag
  (the test confirms exactly one of the 25 shifts works). You cannot skip the
  classical layer.
* **Determinism / per-instance.** `K` and the 32-bit session `tag` come from
  `ZSCTF_SEED`; the flag comes from `ZSCTF_FLAG`. Same seed+flag ⇒ identical
  blob; a different seed or a different flag changes it (all asserted). The
  session tag guarantees distinct ciphertexts even for two instances that happen
  to share the same `K`.


## Design notes (for the ZSCTF team)

* **Fresh mechanic.** This is a multi-layer *encoding onion* + a two-step
  classical cipher. It does not reuse any shipped crypto mechanic (it is neither
  single-byte XOR `singlexor`, repeating-key `vigenere`, two-time pad
  `twotimepad`, nor any of the RSA/ECDSA/LWE/knapsack family) — see
  `corpus-genome.yaml`.
* **Per-instance:** `ZSCTF_SEED` → `(K, session tag)`; `ZSCTF_FLAG` → the flag.
* **Harder variants (extrapolation, not shipped):** randomise the *number* and
  *order* of base-N layers per instance (the auto-detect solver still peels
  them); swap the Caesar+Atbash core for a full mono-alphabetic substitution
  (then frequency analysis is required → raises the band); or add a base85 layer
  with an ambiguous alphabet that forces backtracking.
