# Bittern — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/bittern.png
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Bittern — official writeup

**Flag:** `zerosecurectf{keyed_lsb_scatter_undone_by_the_asset_id}` (static demo
seed; per-instance in production)

Bittern is the forensics category's **rigorous steganography** entry: a hidden
message carried by a *verifiable* mechanism, recoverable by signal/structure
reasoning rather than guessing. (A bittern is a wading bird famous for freezing
into the reeds — hidden in plain sight — which is exactly the shape of the
challenge.)


## The scenario

A vendor hands the same product screenshot to many recipients, but silently
**fingerprints** each copy with an invisible, per-recipient forensic watermark —
the real-world practice behind traitor tracing, DRM fingerprinting and
C2PA/provenance tagging. When a copy leaks, the vendor reads the watermark to
learn whose copy it was. Here the watermark payload is the flag.


## The mechanism (nothing hidden by obscurity)

The watermark is **keyed LSB steganography**. Three facts make it rigorous rather
than a guessing game:

1. **Self-verifying frame.** The flag is wrapped as
   `MAGIC("ZSIM") | VER(1) | LEN(2,BE) | FLAG(LEN) | CRC32(4,BE)`,
   CRC over `MAGIC|VER|LEN|FLAG`. Correct recovery proves itself (MAGIC + CRC);
   wrong recovery fails loudly. There is nothing to eyeball or guess.

2. **Keyed embedding positions.** The image exposes 3 LSB slots per pixel (R,G,B).
   Flattened row-major, slot `s` is byte `s` of the `H·W·3` buffer, LSB `= value & 1`.
   The payload bits are **not** laid down in raster order — they are scattered by a
   keystream:

   ```
   ks   = SHA256(assetid || b"zswm/pos|" || ctr_be32),  ctr = 0,1,2,...
   word = next 32-bit big-endian word of ks
   slot = word mod (3·W·H)        # skip repeats
   ```

   The j-th distinct slot carries payload bit j (MSB-first within each byte).

3. **The key is in the file.** The 16-byte `assetid` is written, in the clear,
   into a PNG `tEXt` "Comment" chunk, alongside a terse description of the scheme.
   That chunk is the single discoverable parameter that keys the whole recovery.

Because the *positions* are keyed, a plain raster-order LSB dump is meaningless:
the bits exist in the image but in the wrong order, so `MAGIC` never appears and
the CRC never validates. (The acceptance test proves this directly — check 5.)


## Intended solution

1. **Open the PNG and look at its chunks.** `strings`/`binwalk` find nothing in
   the pixel data. But the `tEXt` "Comment" chunk reads like asset-tracking
   metadata: `ZeroSecure asset watermark v1 | assetid=<32 hex> | lsb map: ...`.
   That both names the hiding place (LSBs) and hands you the key + construction.

2. **Parse the pixels from first principles.** Read `IHDR` (W, H, 8-bit,
   color-type 2 = RGB), concatenate `IDAT`, `zlib`-inflate. Every scanline uses
   filter type 0, so drop the one leading filter byte per row to get the raw
   `H·W·3` RGB bytes. (`solution/solve.py` does this with stdlib `zlib`/`struct`;
   Pillow is not required.)

3. **Rebuild the keyed slot stream** from `assetid` exactly as documented, and
   read LSBs in that order. Bootstrap with the 7-byte header (`MAGIC|VER|LEN`) to
   learn the flag length, then read `LEN+4` more bytes.

4. **Validate and print.** Confirm `MAGIC == "ZSIM"` and
   `crc32(MAGIC|VER|LEN|FLAG) == CRC`. The flag falls out.

```bash
python3 solution/solve.py challenge/bittern.png
# -> zerosecurectf{keyed_lsb_scatter_undone_by_the_asset_id}
```


## Why the intended path is the only cheap one

- **No `strings`/carving shortcut.** The payload is never contiguous bytes: it is
  individual bits spread across the LSB plane. `zerosecurectf{`, the flag, and
  even the frame `MAGIC` are all absent from the raw file (acceptance checks 4–5).
- **No plain-LSB shortcut.** The classic "dump all LSBs in order" move yields the
  natural image LSBs with ~500 payload bits scattered through them — no frame, no
  flag. Recovery requires reproducing the keystream, i.e. actually using the key.
- **No brute force.** The slot order is a keyed permutation over ~1.2M slots; you
  do not search it, you *derive* it from the in-file `assetid`. Guess-exposure is
  ~1: every step has a reasoning handle (the metadata discloses the construction;
  the frame's MAGIC/CRC confirm correctness), per the §8 guessiness target.


## Design notes (for the ZSCTF team)

### Lineage

- **Fills a verified corpus GAP.** The forensics taxonomy lists *Rigorous
  steganography — "information hidden with a verifiable mechanism; signal
  reasoning (no guessing)"* as a primitive class (system.html §16, forensics
  table), yet the corpus note records that **"No rigorously designed,
  difficulty-evidenced steganography challenge could be verified — none was added
  to pad the list"** (system.html §16, Forensics/DFIR corpus note). Bittern is
  therefore partly **EXTRAPOLATE** (§10/§17.3): it pushes outside the existing
  corpus point-cloud into the named-but-empty stego slot. The extrapolation is
  disciplined — grounded by a concrete, reproducible keyed mechanism and a real
  scenario, not novelty for its own sake.
- **Operators applied** (system.html §17.3):
  - **GROUND** (G9,G3): attach a real scenario + technique lineage — forensic
    watermarking / traitor tracing on a "leaked screenshot." (Authenticity ↑↑.)
  - **CONSTRAIN** (G4): gate recovery behind a keyed parameter so the obvious
    path (raw LSB dump) fails and the solver must reason from the in-file key —
    without introducing an arbitrary rule (the key and construction are
    disclosed, so guessiness stays ~1).
  - **PARAMETERISE** (any knob): expose `ZSCTF_SEED` → per-instance asset id,
    keystream and scatter; enables unique per-recipient instances (§9 lever).
- **Sibling coherence.** Bittern is a deliberate **SUBSTITUTE-PRIMITIVE** neighbour
  of the forensics audio stego *Whistler*: Whistler keys the *values* at fixed
  positions (MFSK tones whitened by a keystream); Bittern keys the *positions*
  while leaving values in the clear (keyed LSB scatter). Same corpus slot, two
  distinct, non-overlapping cruxes — so neither is a template of the other.

### Honest difficulty band — **Hard**

Scored on the §8 axes: breadth 2 (PNG structure + a keyed keystream), depth 3
(from-scratch PNG parse + exact keystream reproduction), tooling 4 (standard
tools do *not* finish it — `zsteg`/`stegsolve` assume unkeyed LSB; you must write
the keyed extractor), search 1 (no brute force), chain 2, **guessiness 1**
(target), novelty 3, authenticity 4. By the §8 band definitions this is **Hard**
("a strong individual solves in hours; typically solvable by a capable agent"),
not Extreme — and the `challenge.yml` records it as such. We do **not** inflate
it: once the in-file comment is found, the scheme is fully reconstructable, so the
difficulty is in doing the forensics correctly, not in a leap of insight.

### RED-TEAM / AI-RESISTANCE

**What a current agent would do.** An agent that inspects PNG chunks will find the
`tEXt` comment, which discloses the asset id and the keystream construction. From
there a capable coding agent can implement the keyed extractor and solve it. So
we are explicit: **Bittern is not AI-*resistant* in the Frontier sense — it is
expected to be agent-solvable.** Its role on the §9 axis is *transfer-resistance*,
not *solve-resistance*:

- **Per-instance parameterisation** (§9 lever; evidence: Evolve-CTF
  semantics-preserving transformations). A memorised or leaked solution for one
  recipient's file does not transfer: a different seed ⇒ different asset id ⇒
  different keystream ⇒ different scatter and different bytes. An agent must
  re-derive the extraction per instance from that instance's own in-file key.
- **No public writeup to recall.** The scheme is bespoke (custom frame, custom
  `zswm/pos|` keystream), so training-data recall of a known stego tool does not
  shortcut it; off-the-shelf `zsteg`-style extractors fail because they assume
  unkeyed, raster-order LSB (demonstrated by acceptance check 5).
- **Honest limits.** The in-file disclosure is a deliberate anti-guessiness
  choice that *lowers* the ceiling: it keeps guess-exposure at the §8 target of 1
  at the cost of making the method discoverable. That is the right trade for a
  category **on-ramp** (§17.7: every category needs a Hard entry) — it rewards
  careful forensics over lucky guessing.

**Pre-release red-team checklist (per §9).** (a) Run current agents; expect
success and **log the failure/near-miss modes** (common ones: reading LSBs in the
wrong bit order, forgetting to skip the per-row filter byte, or missing the
"skip repeats" rule — each caught by the self-verifying frame). (b) Re-test on
each major model release — AI-resistance is perishable (§9 known hazard). (c)
Contamination watch after any public writeup leaks.

### Harder variants (extrapolation neighbours → Extreme/Frontier)

Tracked for a future Extreme sibling; each keeps guessiness bounded by leaving a
reasoning handle:

- **Withhold the construction (CONCEAL-SHIFT ↑).** Store only the `assetid` (or
  derive it from an EXIF/XMP field) and *not* the scheme text. Recovery then needs
  LSB-plane **steganalysis** (chi-square / sample-pairs to localise the modified
  slots) plus reverse-engineering the keystream — pushing toward Extreme. Risk:
  guessiness if no tell is left; mitigate by keeping the self-verifying frame as
  the oracle and the asset id discoverable.
- **Key the key (CHAIN).** Make the asset id itself the output of a first stage
  (e.g. recovered from a sibling artifact), so Bittern becomes stage 2 of a
  forensics chain (§17.5 pattern).
- **Harden the carrier (SUBSTITUTE-TARGET).** Embed in a JPEG's DCT coefficients
  instead of PNG LSBs so the watermark survives lossy recompression — closer to
  production forensic watermarking and markedly harder to extract.

### AI note

On uniform/known-tool stego an agent solves from memory; Bittern's bespoke keyed
construction and per-instance asset id are what force genuine modelling of *this*
file rather than template recall (system.html §9). It is a measurement-leaning,
transfer-resistant Hard on-ramp — the deliberate counterpart to the resistance-
leaning Extreme/Frontier entries.
