# The Doombot Token — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

The narrative gate answer is **`doombots`**. In `challenge/`, run `python open.py gate.bin "doombots"` to render the puzzle. The reference solver can also use the identical rendered handout retained in `solution/unlocked/`. The launcher fixes the original station identifier so that renaming the outer folder does not change the gate key.

1. Open the narrative gate with **doombots**.
2. The token is `IV || C0 || C1`; the authorization text is in the plaintext block recovered from `C1`. The preceding plaintext block is explicitly ignored.
3. CBC decryption gives `P1=D(C1) XOR C0`. XOR the eight `C0` bytes at offsets `5..12` with `peasant; XOR overlord`.
4. This sets the checked text to `role=overlord` without learning the AES key. Submit the forged token. The archived accepted answer is retained separately; the solver never reads the Guard’s private key.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
