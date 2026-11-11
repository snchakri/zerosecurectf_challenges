# Staged Hint Ladder: Predictable Entropy Leak

### Hint Level 1 (Orientation)
The nonces are raw 32-bit outputs of MT19937 (exactly `random.getrandbits(32)`).
MT19937 keeps 624 words of internal state. How many consecutive outputs were you
handed? That number is not an accident.

### Hint Level 2 (Reframe)
Each 32-bit output is a *tempered* view of one state word. The tempering step is
a fixed sequence of shifts/XOR/AND masks, and every one of those steps is
invertible. Recover the 624 state words and you have a perfect clone of the
engine — no seed required.

### Hint Level 3 (Strong Nudge)
Load the 624 recovered words back into a generator positioned to twist next
(index 624), then keep drawing from it exactly as `generator.py` documents: the
sealing keystream is the next outputs, four big-endian bytes per word, XORed
over the vault. Re-derive that keystream and peel the seal off `sealed_vault.hex`.

---
*Note: Crux Floor invariant — the untempering and the forward replay are the
reasoning the challenge is testing; each hint restores a handle, never the whole
ladder.*
