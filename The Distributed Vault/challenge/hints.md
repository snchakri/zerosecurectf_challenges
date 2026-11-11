# Staged Hint Ladder: The Distributed Vault

### Hint Level 1
Shamir's Secret Sharing represents the secret as the constant term f(0) of a degree k-1 polynomial.

### Hint Level 2
Use Lagrange interpolation over field GF(p) with 5 valid shares.

### Hint Level 3
Evaluate L(0) = sum( y_j * prod( -x_m / (x_j - x_m) ) mod p ).

---
*Note: Crux Floor invariant: The core cryptographic insight is never handed out completely; each hint restores a reasoning handle.*
