# Staged Hint Ladder: Kerberos AS-REP Roasting Capture

### Hint Level 1
When Kerberos pre-authentication is disabled, an adversary can request an AS-REP ticket without knowing the user's password.

### Hint Level 2
The AS-REP message contains a section encrypted with the user's password hash (etype 23: RC4-HMAC).

### Hint Level 3
Extract the ticket payload formatting.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
