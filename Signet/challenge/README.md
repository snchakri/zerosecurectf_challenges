# Signet

**Category:** Cryptography

A firmware-update signing service derives per-request ECDSA nonces on a secret but linear schedule; recover the key from three signatures, then use it to redeem Shamir shares (each gated behind a signature over a distinct attestation token) and reconstruct the flag offline.

**Connect:** `nc <challenge-host> 30024`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
