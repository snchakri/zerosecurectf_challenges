# The Linear Differential Trail — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Linear Differential Trail (FEAL-4 differential cryptanalysis)


## 0. Scope note
This is a reduced-width FEAL-4: a 4-round Feistel on a 32-bit block with four
16-bit round keys and FEAL's signature round function (byte add mod 256 then
`ROL2`). The reduced width keeps the self-contained solver fast and the key
search tractable while preserving the authentic FEAL differential attack
structure (choose input differences, peel the last round key, repeat).


## 1. The differential hook
S-boxes are `S0(a,b)=ROL2((a+b)&0xff)`, `S1(a,b)=ROL2((a+b+1)&0xff)`. Addition is
non-linear over XOR, but adding `0x80` equals XOR `0x80` mod 256 (bit 7 flips, no
carry propagates further), so an `0x80` difference in an addend yields a fixed
`ROL2(0x80)=0x02` output difference with probability 1. Combinations of such
differences give the cipher strongly biased differential characteristics.


## 2. Characteristic and last-round recovery
With input difference `alpha = 0x8080` placed in the left half (right-half
difference 0), round 1 is deterministic and the full 3-round characteristic
`alpha → 0x000288a8` holds with probability ≈ 0.12. The last-round attack:
- The round-4 input is `L4` (the ciphertext left half), and
  `L3 = R4 ⊕ F(L4 ⊕ K3)`. The round-3 *right* difference `ΔR3 = ΔL4` is observable
  without any key, so pre-filter "right pairs" by the most common `ΔL4`.
- For each candidate `K3` (2^16), invert round 4 for those pairs and histogram
  `ΔL3`. The correct `K3` makes one value (the characteristic `ΔL3`) spike;
  rank by that peak and keep the top candidates (the differential pins the key
  only up to a small set, so keep several).


## 3. Peeling to the end
Peel round 4 with each `K3` candidate; attack `K2` the same way on the resulting
3-round transcript. After stripping two rounds you have a 2-round Feistel whose
plaintexts are known, and the round function relations give `K0`, `K1` directly:
```
L2 = R1 = L0 ⊕ F(R0 ⊕ K0)  ⇒  F(R0 ⊕ K0) = L2 ⊕ L0
R2 = R0 ⊕ F(R1 ⊕ K1)       ⇒  F(L2 ⊕ K1) = R2 ⊕ R0
```
Invert `F` by table lookup to read off `K0`, `K1`. Validate the full
`(K0,K1,K2,K3)` against the whole transcript.


## 4. Equivalent keys
The cipher has exactly-equivalent keys (e.g. XORing `0x8080`/`0x0002` into
`K0/K1/K2` in a fixed pattern yields the identical permutation). The attack may
return such an equivalent key; that is fine — it defines the same cipher and
therefore the same CTR keystream, so it decrypts the flag correctly.


## 5. Flag recovery
`keystream_block_i = encrypt_block((nonce + i) mod 2^32, K)`; XOR over
`flag_ct_hex` (big-endian, 4 bytes/block) to recover the flag.


## 6. Solver & Verification
```bash
python solve.py --dist ./dist     # ~4 seconds
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (clean room of
`dist/` + `solve.py`). The solver implements the cipher (via `cipher_spec.py`),
the differential key recovery, and CTR decryption from scratch.


## 7. Citations & References
- Biham, E. & Shamir, A. (1991). *Differential Cryptanalysis of DES-like
  Cryptosystems.* J. Cryptology — includes the FEAL attacks.
- Shimizu, A. & Miyaguchi, S. (1988). *Fast Data Encipherment Algorithm FEAL.*
  EUROCRYPT (the FEAL round function).
- Jon King, *A Tutorial on Differential Cryptanalysis of FEAL-4* (a classic
  step-by-step public treatment).


## 8. Defense Engineering & Remediation
FEAL-4 is a teaching break: too few rounds and an addition-based round function
with exploitable differentials. Modern ciphers (AES) use many rounds and
S-boxes with provably bounded differential probability. Never deploy reduced-
round or home-rolled ciphers; use vetted primitives with wide security margins.
