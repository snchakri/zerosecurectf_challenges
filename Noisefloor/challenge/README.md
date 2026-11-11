# Noisefloor

**Category:** Cryptography

A post-quantum "lockbox" KEM seals the flag under an LWE keypair, but the vendor chose a modulus ~2^20 with only +-1 noise -- pushing the error below the security noise floor. Recover the ternary private key from the public key by lattice reduction. The AES-256-GCM key is SPLIT: it binds that secret AND the secret of a second, independent LWE lockbox, so a clean primary solve alone cannot decrypt -- you must solve a second lattice to earn the other half of the key.

**Download the attached file** and recover the flag.
