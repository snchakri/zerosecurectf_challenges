# Windage

**Category:** Cryptography

A maritime navigation beacon ECDSA-signs its status reports, but its RNG has a fixed "windage": the top few bits of every nonce are zero. Each signature is valid, yet the bias turns the set into a Hidden Number Problem -- recover the private key by building the HNP lattice from many signatures and running LLL. The flag is then CRT-split across coprime moduli: each residue is released only for a valid, modulus-bound attestation signature (needs the recovered key), and you CRT-reconstruct the flag offline from all of them.

**Connect:** `nc <challenge-host> 30030`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
