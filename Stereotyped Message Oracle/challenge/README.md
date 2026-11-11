# Stereotyped Message Oracle

**Category:** Cryptography

Doom's field directives are encrypted with a careless RSA profile: public
exponent `e = 3`, no randomised padding. Each dispatch follows a rigid house
style — a fixed bureaucratic header, then the sensitive token verbatim.
CICADA3301 lifted one ciphertext and the template that produced it. The header
is fully known; only the trailing token is secret. With such a small exponent
and so much known plaintext, the cube is nowhere near wrapping the modulus where
it matters, and the unknown tail is a *small root* waiting to be lifted.

Your objective: recover the secret tail of the dispatch — which is the flag.

**Download the attached file** and recover the flag.
