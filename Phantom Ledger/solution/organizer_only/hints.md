# PHANTOM LEDGER — Hint Progression

This is the hardest challenge. Four hints are appropriate.
Space them out by 30-45 minutes each. Do not release all at once.

---

Hint 1  (release freely or after 20 min)
"You have three binary captures. Start by XOR-ing them against each other.
 What does the result tell you?

 In AES-CTR, ciphertext = plaintext XOR keystream.
 If two messages use the SAME keystream:
     ct1 XOR ct2 = pt1 XOR pt2   (keystream cancels out)
 A region of zero bytes in ct1 XOR ct2 means those bytes
 of pt1 and pt2 are identical."

---

Hint 2  (after 45 min or on request)
"The infrastructure notes say the relay crashed and rebooted a SECOND time
 on March 21st. Read server.py carefully. What does a process restart do to
 the module-level _counter variable? What does that mean for the nonce?

 Focus on night1 and night2. night0 is from a different relay instance
 with a different daily key. XOR-ing night0 with night1 or night2 will
 produce random noise -- this is expected and intentional."

---

Hint 3  (after 90 min or on request)
"You have a known-plaintext header to start recovering the keystream.
 But to decrypt night2 fully, you need to extend the keystream further.
 To extend it, you need to know more of night1's plaintext.

 The relay_diagnostic.txt has more than one session in it.
 Read the whole file carefully. The diagnostic mode was active
 more than once -- and it logged what it saw each time."

---

Hint 4  (after 135 min or on request)
"You have decrypted night2's plaintext. There is a base64-encoded blob
 inside it after 'Decode: '. Decode the blob to raw bytes.

 The server.py docstring mentions that outbound packages are keyed to
 the session date for chain-of-custody verification.
 The relay_diagnostic.txt records chain-of-custody metadata for each session.
 Look at what that metadata contains and how it is derived.
 Apply the same derivation to the correct session date."
