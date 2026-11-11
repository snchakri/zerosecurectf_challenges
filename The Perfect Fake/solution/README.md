# The Perfect Fake — solution

1. Load `model.npz` with NumPy using `allow_pickle=False`.
2. Inspect the model arrays, `vault`, and `loader_cap`. The first 32 raw words of `W2` have an unusual bit pattern; the loader cap is 32 while the vault has 68 bytes.
3. The brief describes recovering a deep-layer key and using a loader overflow to reveal the encrypted record.

## Archive limitation

The loader/runtime and the vault encryption specification are absent from the preserved handout. The local archive contains the model and accepted answer, but no independently verified complete recovery procedure.

`accepted_flags.txt` is the event scoring record, not a substitute for cryptographic recovery.
