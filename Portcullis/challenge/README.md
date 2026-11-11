# Portcullis

**Category:** Web Exploitation

An SSO gatehouse issues RS256 JWT session tokens and publishes its RSA public key for verification; its verifier trusts the token's own `alg` header and reuses that public key as an HMAC secret for HS256, so a forged HS256 token signed with the public-key bytes is accepted as admin and the admin console hands over the flag.

**Connect:** `http://<challenge-host>:30065`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
