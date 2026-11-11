# The Rupture — solution

1. The riddle describes **Latveria**. Run `python open.py gate.bin latveria` from `challenge/` to unlock `photo.png`; the identical rendered image is retained in `solution/unlocked/`.
2. Inspect PNG text metadata. Its GPS text is a decoy; the scene is a Doomstadt ferry.
3. Flatten RGB channel values in row order and take each channel's least significant bit.
4. Try bit alignments 0 through 7 and group each eight bits most-significant-bit first. Alignment 4 contains the flag.

```bash
python -m pip install Pillow
python solution/solve.py
```
