# WARD 7 — Hint Progression

---

Hint 1 — 0 points deduction  (release freely or after 20 min)
"Look at keystore.txt carefully. Both administrators have public keys.
 Compare the values. Is there anything unusual about them?"

---

Hint 2 — 15 points deduction  (after 40 min or on request)
"When two RSA public keys share the same modulus n (same large number)
 but different exponents e1 and e2, and the same plaintext is encrypted
 with both, there is a classical attack that recovers the plaintext
 without knowing either private key.

 Search: 'RSA common modulus attack'"

---

Hint 3 — 30 points deduction  (after 75 min or on request)
"Extended Euclidean Algorithm on (e1, e2):
     find a, b  such that  a*e1 + b*e2 = 1
     then: m = c1^a * c2^b  mod n
 If a or b is negative, use modular inverse:
     c^(-k) mod n  =  modinv(c, n)^k mod n

 After recovering the plaintext document, read it carefully.
 The document itself tells you how the final encoding works.
 The case reference number contains the key -- use its digits,
 one by one in sequence, as successive shift values for each
 alphabetic character."

