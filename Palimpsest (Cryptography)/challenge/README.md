# Palimpsest

**Category:** Cryptography

A central audit-log collector seals every record with AES-256-GCM under one FIXED, reused nonce; from two records recover the GHASH authentication key H by solving a polynomial over GF(2^128) (the "forbidden attack"). H is only the MEANS to extract: forge valid tags for point-bound "disclose:flag:<i>" directives to release evaluations P(x_i) of a secret GF(2^128) disclosure polynomial whose coefficients encode the flag; collect k of them and Lagrange-interpolate offline.

**Connect:** `nc <challenge-host> 30022`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
