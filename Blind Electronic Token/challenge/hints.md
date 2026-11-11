# Staged Hint Ladder: Blind Electronic Token

### Hint Level 1
In Chaum's blind signature scheme, the user computes m' = m * r^e mod N using a random blinding factor r.

### Hint Level 2
The signer returns s' = (m')^d = (m * r^e)^d = m^d * r mod N.

### Hint Level 3
Compute s = s' * r^(-1) mod N to recover the valid signature m^d mod N without the signer seeing m.

---
*Note: Crux Floor invariant: The core cryptographic insight is never handed out completely; each hint restores a reasoning handle.*
