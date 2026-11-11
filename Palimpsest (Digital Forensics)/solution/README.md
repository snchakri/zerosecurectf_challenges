# Palimpsest — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py challenge/palimpsest.zip
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Palimpsest — official writeup

**Flag (static demo seed):** `zerosecurectf{the_central_directory_lies_carve_the_local_headers}`
(per-instance in production — the flag is injected from `ZSCTF_FLAG`).


## The phenomenon

A ZIP archive describes its contents **twice**:

- a **local file header** (signature `PK\x03\x04`) sits inline with each file's
  data, scattered through the body of the archive;
- a **central directory** at the end (a run of `PK\x01\x02` records terminated by
  the `PK\x05\x06` end-of-central-directory record) is an authoritative *index*
  that lists the files and points to their local headers.

(Structure per PKWARE's *APPNOTE.TXT* — the ZIP specification — §4.3.7 local
header, §4.3.12 central directory header, §4.3.16 end-of-central-directory.)

Every standard extractor — `unzip`, Python `zipfile`, Windows Explorer, macOS
Archive Utility — reads **only the central directory** to decide what files
exist. None of them scans the body for stray local headers. So if a file's local
header and data are physically present but the central directory does not list
them, that file is **invisible to normal tools** while remaining fully intact on
disk. These are *orphaned* / unreferenced entries.

This is a real forensic artifact, not a contrivance. "Removing" a file from an
archive, or an interrupted/rewritten save, can leave the old local record in
place while only the index is updated. The recovery direction is equally real:
Info-ZIP's `zip -FF`/`-F` ("fix archive") modes exist precisely to **rebuild a
central directory by scanning for local headers**, which only works because the
local data survives independently of the index. Palimpsest is that situation,
made the whole point of the challenge.


## Why `strings` and a naive `unzip` find nothing

- `unzip -l` / `zipfile.namelist()` read the central directory → they list only
  the four benign visible files (`README.txt`, `CHANGELOG.md`, `assets/icon.png`,
  `drafts/old-notes.txt`). None contains the flag. `unzip -t` reports "No errors"
  because it only validates the four indexed entries; it never notices the
  orphans.
- `strings` / a raw byte-scan find no flag because the payload is **DEFLATE-
  compressed** before being stored, so the flag text appears nowhere as bytes.
  The compressed blob is also **split and shuffled**, so even the compressed form
  is not contiguous in the file.


## How the payload is hidden (mechanism)

1. The flag is wrapped in a self-verifying frame:
   `MAGIC "ZPLM" | VER(1) | FLEN(2,BE) | FLAG | CRC32(4,BE)`.
2. The frame is compressed with zlib into one high-entropy blob.
3. The blob is cut into `N` contiguous segments (`N` = 5–9 and the cut points
   both derive from the per-instance seed). Each segment is stored verbatim as
   the data of its **own orphaned local header** (method 0 = STORED). A single
   segment on its own is a meaningless slice of a DEFLATE stream.
4. The segment records are written to the body in a **seed-shuffled** order, so
   on-disk order ≠ logical order.
5. One more orphan is a **residual index**: its data is
   `MAGIC "ZPMF" | VER | N | CRC32[0..N-1] (BE, logical order) | CRC32(self)` —
   the CRC-32 of each segment's bytes in the correct order.
6. The central directory lists only the four benign files. The `N` segment
   orphans and the index orphan are never referenced.


## The intended solution

1. **Open it the normal way.** `zipfile` lists four files. Record each visible
   entry's local-header offset (`ZipInfo.header_offset`).
2. **Count the real local headers.** Scan the raw bytes for `PK\x03\x04`. There
   are more than four — e.g. 11 headers for the demo seed, so **7 are orphaned**.
   This gap is the crux: the index is hiding entries that are physically present.
3. **Parse and validate each carved local header.** Read method / name / sizes /
   CRC, locate the data, and check `crc32(data)` against the header's stored CRC.
   This rejects any `PK\x03\x04` that merely occurs inside compressed data, and
   confirms the orphans are genuine STORED records.
4. **Find the residual index** among the orphans (its data begins `ZPMF`); parse
   the ordered list of segment CRCs.
5. **Reassemble.** For each remaining orphan compute `crc32(data)`, place it in
   the slot the index gives it, concatenate in that order, and `zlib.decompress`
   the result.
6. **Validate.** The inflated bytes are the `ZPLM` frame; check MAGIC and the
   CRC-32, then read out the flag. Wrong assembly fails MAGIC/CRC — so you always
   know whether you are right.

`solution/solve.py` does exactly this, with only the stdlib, and prints the flag.


## Why the intended path is the only cheap one (no guessing — §2 invariant 2)

- **The index gap is not guessable away.** You cannot get the flag from the four
  listed files; you must realise the body holds more local headers than the
  directory admits. That realisation is pure ZIP-format reasoning.
- **A single orphan is not enough.** Each segment is a fragment of one DEFLATE
  stream; it will not inflate alone, and `strings` on it yields nothing.
- **Physical order is a dead end.** The segments are shuffled, so concatenating
  them as carved does not inflate. The *only* information that fixes the order is
  the residual index, and it pins the order by CRC — an exact match, not a guess.
- **Self-verifying end state.** The per-segment CRCs and the frame CRC make every
  intermediate and the final result checkable, so there is no trial-and-error
  acceptance step (guessiness axis ≈ 1).


## Reasoned decoys (§2 invariant 7)

Each decoy is rejectable by a check the solver can run:

- `drafts/old-notes.txt` — looks like it could be "the deleted draft," but it is
  a benign listed file and contains no frame/flag. Rejectable: it is in the
  central directory (not orphaned) and holds no `ZPLM` frame.
- `assets/icon.png` — a valid 8×8 PNG that invites `binwalk`/`strings`/
  carving-for-an-image. It carries no payload. Rejectable: no `ZPLM`/`ZPMF`.
- The `README.txt` / `CHANGELOG.md` story ("I cleaned the old drafts out")
  explains the orphaning benignly and points at it, rather than misdirecting.


## Known unintended paths — closed or blessed (§2 invariant 8)

- **`zip -FF` / `binwalk` carving (BLESSED).** These tools can reconstruct a
  central directory, or carve, the orphaned records, i.e. they can do steps 2–3
  for you. That is a legitimate, expected forensic shortcut and it does **not**
  trivialise the challenge: the recovered segments are still an out-of-order
  split of one DEFLATE stream, so you must still find the residual index, order
  the segments by CRC, concatenate, inflate, and validate the frame (steps 4–6).
  The gate is the reassembly reasoning, not the carving mechanics.
- **Brute-forcing the segment order (CLOSED in practice).** With 5–9 segments a
  human *could* in principle try permutations, but the residual index makes this
  unnecessary and is the signposted path; the CRC match is exact, so ordering is
  never a guess. No instance relies on permutation search.
- **`strings` / raw scan (CLOSED).** The flag is compressed and fragmented; it is
  not present as bytes (asserted by the acceptance test).


## Design notes (for the ZSCTF team)

- **Lineage (corpus-genome.yaml, system.html §17):**
  - `forensics-012 "Artifacts of Dangerous Sightings"` — reconstruct content
    from *residual host/container structure* → operator **GROUND** (§17.3: attach
    a real scenario to the abstraction — here, real ZIP central-directory-vs-
    local-header semantics and the real `zip -FF` recovery path; Δdifficulty ≈ 0,
    Δauthenticity ↑↑).
  - `forensics-011 "randomware"` — "recover data via a structural/format
    weakness, per-instance" → operator **CONSTRAIN** (§17.3: add a visibility
    limit — the solver sees only the one artifact and only what the *index*
    chooses to reveal, forcing structural recovery; the limit is non-arbitrary,
    so guessiness is not introduced).
  - Re-skin per §10 *context re-skin* / *authenticity lift*: the DFIR "incident"
    framing of the seeds is recast as a benign file-format recovery, keeping the
    structural insight while dropping the malware/intrusion surface.
- **Crux:** a ZIP's central directory and its local headers are two independent
  descriptions of the same bytes; standard tools trust only the former, so data
  referenced only by the latter is invisible yet fully recoverable.
- **Primitives:** ZIP container internals (CD vs LFH), signature carving with
  CRC validation, fragment reassembly via a residual index, DEFLATE inflation.
  Loosely CWE-noise aside, this is benign format forensics, not a vulnerability.
- **Distinct from `whistler`:** whistler hides a keyed signal in the *frequency
  domain* of a WAV (DSP + keystream). Palimpsest hides nothing in any sample or
  byte-string; the payload lives in *container metadata structure* (DFIR carving
  + format reasoning). Different discipline, different toolchain, no overlap.


## Harder variants (extrapolation, for a future Extreme sibling)

- **Drop the residual index.** Without `ZPMF`, ordering must be inferred from the
  DEFLATE stream itself (only the true order inflates without error) — raising
  the chain/search axes toward a real reconstruction problem. Keep it fair by
  leaving the final CRC as the oracle. (Operator: `PRUNE` a reasoning handle —
  careful, this flirts with guessiness; gate with the blind-solve, §20.)
- **Overlap the orphans with live data** (polyglot): make a segment's bytes also
  be the tail of a visible entry's DEFLATE stream, so carving must disentangle
  shared regions. (Operator: `CHAIN` toward a crafted-polyglot layer.)
- **Nest a second ZIP** inside an orphan, repeating the trick one level down.
  (Operator: `COMPOSE`/`CHAIN`; raises depth, watch total state vs §9.)

All three are tracked as neighbours; each must re-enter the §2 invariant check
(blind solve + unintended-solution scan + AI red-team) before shipping.
