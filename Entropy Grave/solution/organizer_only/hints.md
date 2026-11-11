# ENTROPY GRAVE — Hint Progression

Four hints. Space them out — do not release all at once.
Suggested timing: H1 freely, H2 after 30 min, H3 after 60 min,
H4 only as last resort after 90+ min with no progress.

---

Hint 1 — 0 points deduction  (release freely)

"Don't try to mount it. Scan it."

→ Single sentence. Points toward file scanning tools (binwalk, strings)
   without naming them. Players on the wrong track (trying to mount
   as filesystem) get corrected immediately.

---

Hint 2 — 20 points deduction

"The wipe wasn't deep enough. Something structured survived.
 Standard forensic tools know how to find it."

→ Points toward binwalk / file signature scanning.
   "Structured" hints at a recognisable file format.
   Does not name binwalk or SQLite.

---

Hint 3 — 40 points deduction

"The log is still readable. Read it carefully.
 In cryptography, an empty entropy pool at key generation time
 is not just an error message. It is a description of the primes."

→ Redirects to the log fragment (found via strings).
   "Description of the primes" is the key phrase.
   A thinking player connects: low entropy -> primes are predictable ->
   look at what's unusual about them.
   Does not name Fermat's factorization.

---

Hint 4 — 60 points deduction  (last resort only)

"When entropy is near zero, both primes are born from almost
 the same seed. They end up unusually close to each other.

 Pierre de Fermat described an efficient factoring method for
 exactly this case in 1643. It starts at the square root of n
 and walks upward looking for a perfect square.

 The ciphertext is in the database. So is everything else you need."

→ Names Fermat. Describes the algorithm at a high level.
   Still requires the player to implement it and handle the RSA decrypt.
   Only release if the player found the database and the log
   but cannot identify the attack after 90 minutes.
