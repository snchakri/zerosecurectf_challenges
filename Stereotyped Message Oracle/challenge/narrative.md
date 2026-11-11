# Challenge: Stereotyped Message Oracle (crypto_11_coppersmith_short_pad)

**Category:** Cryptography
**Difficulty:** Hard
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Doom's field directives are encrypted with a careless RSA profile: public
exponent `e = 3`, no randomised padding. Each dispatch follows a rigid house
style — a fixed bureaucratic header, then the sensitive token verbatim.
CICADA3301 lifted one ciphertext and the template that produced it. The header
is fully known; only the trailing token is secret. With such a small exponent
and so much known plaintext, the cube is nowhere near wrapping the modulus where
it matters, and the unknown tail is a *small root* waiting to be lifted.

Your objective: recover the secret tail of the dispatch — which is the flag.

## Provided Files
- `stereotyped_rsa.json` — `n`, `e` (=3), ciphertext `c`, the known `known_prefix`
  (the house header, ending at the public flag marker), `secret_len` (the byte
  length of the unknown tail), and a note stating the exact message layout.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. The unknown tail is the unique small root of the
  stereotyped equation; it *is* the flag body.
