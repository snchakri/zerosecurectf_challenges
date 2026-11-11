# Janus — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/janus.png
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Janus — official writeup

**Flag:** per-instance (injected via `ZSCTF_FLAG`). The shipped demo artifact
embeds the placeholder `zerosecurectf{REPLACE_ME_AT_DEPLOY}`; the acceptance test
uses `zerosecurectf{janus_two_faces_png_zip_polyglot_ok}`.


## The surprise

You are given one file, `janus.png`. It opens as an image. The twist is that the
*same bytes* are also a valid **ZIP** archive — a **PNG + ZIP polyglot**. And the
flag is reachable only by reading **both** faces and combining them.

```
            +-----------------------------------------------+
  bytes --> |  PNG: sig|IHDR|tEXt|IDAT|IEND  |  ZIP: LFH|data|CD|EOCD  |
            +-----------------------------------------------+
               \__ read front-to-back __/      \__ found from the tail __/
               KEY hidden in pixel LSBs         CIPHER = the entry bytes
```


## Why one file can be two formats

- **PNG is read front-to-back.** It must *start* with the 8-byte signature,
  then `IHDR`, image data, and `IEND`. Decoders stop at `IEND` and ignore
  trailing bytes. So anything appended after `IEND` does not disturb the image.
- **ZIP is read back-to-front.** A reader locates the *End Of Central Directory*
  (EOCD) record by scanning from the end of the file, then follows the central
  directory to each entry's local header. Crucially, if the recorded offsets
  imply the archive starts later than byte 0, a conformant reader (Python's
  `zipfile`) treats the leading bytes as a **prefix** and adds that prefix length
  to every offset.

Put a complete PNG first and a complete ZIP second:

```
artifact = PNG_bytes || ZIP_bytes
```

- As a PNG: signature/IHDR/IDAT/IEND are all valid and first → it renders; the
  ZIP tail is ignored trailing data.
- As a ZIP: the EOCD is literally the last bytes; the central directory's
  offsets are self-consistent for a zip that "starts" at the PNG's length, which
  `zipfile` auto-detects as a prefix → it extracts the entry.

This is the classic, benign PNG+ZIP polyglot. (Verified here: `zipfile.testzip()`
passes and, where Pillow is available, it decodes the image — see


## The two faces, concretely

**Face 1 — the KEY (PNG).** A 16-byte key is embedded in the **least-significant
bits of the first 128 colour samples** of the image, MSB-first per byte. Reading
it requires genuine image parsing: inflate `IDAT`, drop each scanline's filter
byte (filter type 0), read sample LSBs. It is invisible to the eye and is **not**
a `strings`/byte-scan hit.

**Face 2 — the CIPHER (ZIP).** The single entry `payload.bin` holds the
ciphertext. Stored uncompressed, but it is XOR-masked, so the unzipped bytes look
like noise.

**Combine.** Expand a keystream from the key and XOR it into the ciphertext to
recover a self-verifying frame:

```
ks     = SHA256(key || b"janus/xor|" || ctr_be32),  ctr = 0,1,2,...
frame  = cipher XOR ks
frame  = MAGIC "ZJAN" | VER(1) | LEN(2,BE) | FLAG | CRC32(4,BE)
```

Check `MAGIC` and the CRC32; on success, `FLAG` is the flag. A wrong key fails
the magic/CRC, so there is nothing to guess.

The whole scheme (minus the key and flag themselves) is also disclosed in the
PNG's `tEXt` "Comment" chunk, so the path is reachable by reasoning, per the
"no obscurity" rule.


## Steps

1. Notice the second face: `unzip -l janus.png` lists `payload.bin`
   (or `binwalk`/`file` hint at an appended archive).
2. Parse the PNG as an image; read the key from the first 128 sample LSBs.
3. Open the same file with `zipfile`; read `payload.bin` (the ciphertext).
4. Rebuild the keystream from the key; XOR; validate `ZJAN` + CRC32; print `FLAG`.

`solution/solve.py` does exactly this with the standard library only.


## Why the combine step is required (the intended-path argument)

- **Unzip only:** the entry is XOR-masked → noise; no flag, no `zerosecurectf{`
  substring (test check 3a).
- **View/scan only:** the picture shows nothing; the flag is not in the raw bytes
  (3b) and a plain raster LSB dump yields the *key bits*, not the flag, and never
  the `ZJAN` magic (3c). The key is useless without the ciphertext, and vice
  versa.
- Only `XOR(cipher, keystream(key))` produces a frame that passes `MAGIC` + CRC.


## Band justification (honest)

**Hard**, not Medium: the difficulty is the *recognition* that a single file is
two formats and that both must be merged — a step naive single-format tooling
actively hides (viewing "succeeds" and unzipping "succeeds", each yielding a
dead end). Once seen, each half is routine (PNG LSBs; a ZIP entry; an XOR). It is
not Frontier: no novel cryptanalysis or heavy tooling. The breadth (two container
formats + a keystream + a self-verifying frame, chained) and the misdirection
place it at Hard. For an AI solver, the trap is that the first successful
single-format parse looks like progress; the per-instance key is what forces
genuine dual-parsing rather than template recall.


## Harder variants (extrapolation, tracked)

- **Three-way polyglot** (PNG + ZIP + PDF/GIF) where a third face supplies a
  nonce — raises breadth (operator `PARAMETERISE`/`EXTRAPOLATE`).
- **Embed the ZIP *inside* a PNG ancillary chunk** (strict PNG with `IEND` last)
  so `binwalk` at EOF is less obvious — raises the recognition difficulty
  (`SUBSTITUTE-PRIMITIVE` on the layout).
- **Split the key across both faces** (half in pixels, half in a ZIP comment) so
  *each* face is individually incomplete — tightens the "must combine" invariant.


## Design notes (for the ZSCTF team)

- **Lineage:** PNG+ZIP polyglot (`GROUND`) × keyed-LSB + self-verifying frame
  borrowed from forensics/`bittern` (`SUBSTITUTE-PRIMITIVE`: LSBs carry the key,
  not the payload) × the "surprise" misdirection genre (`EXTRAPOLATE`) ×
  per-recipient instancing (`PARAMETERISE`). See `challenge.yml`.
- **Determinism:** hand-rolled PNG (pinned zlib level) and hand-rolled STORED ZIP
  (fixed DOS timestamps) → byte-identical output for a given seed+flag.
- **Safety:** benign throughout — a picture that is also a zip; no executable
  polyglot, no auto-run, no network.
