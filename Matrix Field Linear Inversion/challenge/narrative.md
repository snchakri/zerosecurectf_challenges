# Challenge: Matrix Field Linear Inversion (crypto_07_hill_cipher_known_plaintext)

**Category:** Cryptography
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Latveria's diplomatic corps still clatters out its cables on a brass teletype
that enciphers in blocks of three letters with a 3x3 matrix over the 26-letter
alphabet — a Hill cipher, elegant and antique and fatally linear. CICADA3301
lifted a full cable off the wire. A handler inside the ministry confirms the
cable opens with a fixed courtesy header. That single leak of plaintext against
ciphertext is enough to peel the key matrix straight out of the algebra, and the
citadel seals its flag vault under that very matrix.

Your objective: recover the 3x3 key matrix, then open the vault.

## Provided Files
- `intercepted_hill.txt` — the intercepted Hill ciphertext (A–Z).
- `intelligence_note.txt` — the confirmed plaintext header.
- `flag_vault.json` — the flag sealed with AES-256-GCM under a key derived from
  the recovered matrix, with the exact sealing recipe stated.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. The key matrix is uniquely determined by the known
  plaintext, and it fully opens the vault.
