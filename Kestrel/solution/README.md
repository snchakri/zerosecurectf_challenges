# Kestrel — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/kestrel.png
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Kestrel — organizer writeup

**Category:** forensics · **Band:** Easy (honest; justified below) · **Flag:** `zerosecurectf{...}`


## The mechanism

`challenge/gen.py` hand-writes a PNG with these chunks, in order:

```
signature | IHDR | tEXt(Software) | tEXt(Capture-ID) | tEXt(Note=DECOY) | IDAT | zTXt(Comment=REAL FLAG) | IEND
```

- **tEXt** is uncompressed Latin-1 text (PNG spec §4.2.3.1). The `Note` chunk,
  near the top of the file, carries the decoy `zer0securectf{...}`.
- **zTXt** is the same but zlib-compressed (spec §4.2.3.4): `keyword 0x00
  compression_method(=0) zlib(text)`. The real flag is a substring of that
  compressed text, so on disk it exists only in deflated form.

That is why `strings`, `grep`, and a raw byte-scan surface the decoy but never
the real flag — the real bytes are DEFLATE output, not ASCII.


## Intended solve (minutes)

Any PNG-aware tool inflates zTXt for you:

```bash
exiftool kestrel.png                 # Comment: ...verified observer note: zerosecurectf{...}
pngcheck -t -v kestrel.png           # prints the zTXt chunk, decompressed
python3 solution/solve.py kestrel.png   # stdlib: parse chunks, zlib.decompress zTXt, regex the flag
```

The reference solver accepts only a candidate matching
`^zerosecurectf\{[a-z0-9_]+\}$`, so the decoy is rejected automatically.


## Why the band is honestly EASY

- **One step, one standard idea:** "metadata can be compressed; use a metadata
  tool, not `strings`." No keystream, no math, no custom framing to reverse. All
  `difficulty_axes` are 1 except `tooling` (2, because you need a PNG-aware tool
  or two lines of zlib) and authenticity.
- **No guessing:** the plaintext `Note` chunk literally says *"full capture notes
  are stored in the compressed metadata (zTXt)"*, pointing straight at the
  mechanism. The flag is self-evident once inflated.
- It is **not a gimme:** a player who only runs `strings` finds the decoy, and
  the decoy fails the format rule, so blindly submitting the first flag-looking
  string loses. Reaching the real flag requires inflating zTXt. (Verified by


## Decoy (the single bounded §7 decoy)

The `Note` tEXt chunk contains `zer0securectf{trailcam_note_<seed8>_not_valid}`.
It is flag-*shaped* but begins `zer0securectf{` (digit zero), so it cannot match
`^zerosecurectf\{[a-z0-9_]+\}$`. The test asserts `strings` reveals this
look-alike, that it differs from the real flag, and that it fails the format
regex — while the real flag is absent from both the raw bytes and the `strings`
output.


## Acceptance

determinism, byte-sanity ×2, strings-safe ×2, per-instance ×3).

Shipped artifact `challenge/kestrel.png`:
`sha256 06d8a1073f665945631980248041c68a0a7805edd86d66a950c98f927448506c`
(generated with the benign demo flag
`zerosecurectf{ztxt_hides_from_strings_use_the_right_tool}`; regenerate per team
with `ZSCTF_SEED`/`ZSCTF_FLAG`).
