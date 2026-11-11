# The Thirteenth Crossing — solution

1. Recover the flag from The Static.
2. Make a set of the `name` fields from `manifest.json`.
3. Find ledger entries whose names are absent from that set: the unmatched entry is `Ilya Strange`, crossing `307910`.
4. Its `residual` is the encrypted payload; the intended key input is The Static's flag.

## Archive limitation

The residual cipher envelope and key derivation are not specified by the preserved handout. No complete author decoder was found locally. The unmatched record and accepted answer are preserved; decryption was not verified.

`accepted_flags.txt` is the event scoring record, not a substitute for cryptographic recovery.
