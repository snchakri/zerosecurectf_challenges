# NULL STREAM — Hint Progression

Four hints. Space them out — do not release all at once.
Suggested timing: H1 on request or after 20 min, H2 after 45 min,
H3 after 75 min, H4 only as last resort after 100+ min.

---

Hint 1 — 0 points deduction  (release freely)

"Run it on something you already know.
 An input you control. See what comes out the other side."

→ Nudges toward dynamic analysis / known plaintext.
   Does not name the cipher type or any tool.

---

Hint 2 — 20 points deduction

"Whatever this is, it shifts bits and feeds them back into itself.
 Old design. Pre-AES. Engineers used to think simple meant safe.
 The output of each step feeds the next."

→ Points toward LFSR concept without naming it.
   "Shifts bits and feeds them back" is the key phrase.

---

Hint 3 — 40 points deduction

"Linear Feedback Shift Register. 32-bit.
 There are two main forms: Fibonacci and Galois.
 The difference between them matters here.
 Shift first. Then decide whether to XOR.
 The constant you need is in the binary."

→ Names LFSR and the Galois variant.
   Still requires the player to extract TAP_MASK and seed derivation.

---

Hint 4 — 60 points deduction  (last resort only)

"The tap mask is 0x80200003. It is the immediate value
 in the XOR instruction inside the cipher loop.

 The seed is not hardcoded. It is derived from the nonce
 in the file header: XOR the first four bytes (as a LE uint32)
 with the last four bytes (as a LE uint32).

 Header layout: NULLSTRM (8 bytes) || nonce (8 bytes) || ciphertext.
 Decrypt from byte 16 onward."

→ Near-complete spoiler. Last resort only.
   If a player uses this, they learn almost nothing.
   Only release if the player has been stuck for 90+ minutes
   with no progress.
