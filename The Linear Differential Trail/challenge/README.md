# The Linear Differential Trail

**Category:** Cryptography

Doom's field units run a stripped-down FEAL cipher — four Feistel rounds whose
round function leans entirely on byte addition and a two-bit rotate. The engineer
who ported it to the citadel's 32-bit telemetry bus believed four rounds "more
than enough." A CICADA3301 asset with access to the encryptor ran a stack of
chosen plaintexts through it — each paired with a partner that differs by a
single fixed mask — and logged every ciphertext. Separately, the unit's broadcast
key streams the citadel's flag.

Addition leaks structure under XOR differences. Trace how a chosen input
difference marches through the rounds, peel the round keys off one layer at a
time, and the key that drives the keystream is yours.

**Download the attached files** and recover the flag.
