# Crossed Signals — solution

1. Solve The Prime Hour, The Thirteenth Name, The Ash Gate, and The Hall of Wards. Their flags are the four key inputs.
2. Read `traffic.json` and group the opaque blobs by source server.
3. Identify the real fragments by authenticated/magic-tag validation after decryption, discard noise, and concatenate by fragment index.

## Archive limitation

The player handout gives dependencies but omits the exact key derivation, nonce layout, and fragment envelope. No author implementation or complete writeup was found locally. The accepted answer is retained, but an independent artifact-to-flag solve was not verified.

`accepted_flags.txt` is the event scoring record, not a substitute for cryptographic recovery.
