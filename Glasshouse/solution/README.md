# Glasshouse — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --bundle challenge/glasshouse
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Glasshouse — official writeup 

**Flag (demo seed `glasshouse-demo`):** `zerosecurectf{tr4c3d_thr0ugh_th3_gl4ssh0us3}`
(per-instance in production — derived from `ZSCTF_SEED` + `ZSCTF_FLAG`).

> **Synthetic-data statement.** Every persona, handle, display name, pen name,
> domain, and certificate serial in this challenge is fictional and generated
> deterministically from a seed. None of them refers to any real person,
> account, or organization. The only real-world data are the published decimal
> coordinates of famous **public** landmarks (coordinates only — nothing
> private), used to model an offline reverse-geocode. The challenge is 100%
> offline: the solver reads local files and never performs any network action.


## Band: medium (honest)

- **Depth:** moderate — the cryptographic lock is a straightforward
  SHA-256-keyed stream cipher with an HMAC tag; the *difficulty is the OSINT
  correlation*, not the maths.
- **Breadth:** 6 artifact files of 4 different kinds (HTML, JPEG/EXIF, PDF,
  JSON) plus an offline gazetteer.
- **Search/guess:** low. The persona leaks their own key recipe in a pinned
  post, so the intended path is *reachable by reasoning*, not guessing. The band
  sits at medium because a solver must (a) hand-parse EXIF GPS, (b) do an offline
  reverse-geocode, (c) pull PDF metadata, and (d) reject a plausible decoy —
  four distinct OSINT sub-skills chained, none individually hard.


## The intended correlation chain

The persona's own recipe (stated in `profile_devforum.html`):

```
K = sha256( handle ":" place ":" author ":" serial )
```

Each token comes from a **different** artifact, so no single file is enough:

1. **handle** — the three profile pages share one handle. `profile_microblog.html`
   explicitly states *"my only real handle is `@<handle>`"* and warns that
   `@<handle>-official` is **not** them. → authoritative handle.

2. **place** — parse `field_01.jpg`'s synthetic EXIF (TIFF/APP1, little-endian):
   - the **Artist** tag equals the authoritative handle → confirms the photo's
     owner and kills the impersonator claim;
   - the **GPS** IFD gives latitude/longitude in degrees/minutes/seconds.
   Convert to decimal and find the nearest row in `gazetteer.json` (globally far
   apart, so the match is unambiguous). Use that row's `slug` (e.g.
   `charminar`).

3. **author** — read `/Info /Author` from `journal.pdf` — the persona's reused
   pen name (e.g. `slate.willow`).

4. **serial** — in `ct_log.json`, pick the entry whose SAN is the persona's own
   subdomain `<handle>.<domain>.example` and read `serial_hex`. **Not** the
   look-alike `<handle>-official.<domain>.example` entry.

Then `K = sha256("handle:slug:author:serial")`, verify the HMAC tag in
`vault.enc`, XOR-decrypt the ciphertext → the flag. The reference solver
(`solution/solve.py`) does exactly this with pure stdlib (its own EXIF parser — no
Pillow).


## The one bounded decoy

`@<handle>-official` is an impersonator account mentioned in the HTML and holding
its **own** TLS cert in `ct_log.json` (different serial, issuer "Lookalike Trust
Services"). It is designed to look like the right pivot.

**Why it is rejectable by reasoning:** the impersonator never possessed the
original photo — the EXIF **Artist** of `field_01.jpg` is the real handle, not
`-official`. The HTML also states outright which handle is real. Using the decoy
handle or the decoy serial changes `K`, the HMAC tag fails, and the vault refuses
to open — so the decoy is both *reasoned out* and *mechanically detectable*.


## Why reassembly is the crux (unintended-path scan)

- **Single-artifact shortcut:** impossible. The key needs four tokens from four
  artifacts; the test flips each token independently and confirms the vault
  refuses to open (`wrong handle/place/author/serial alone fails`).
- **`strings`/`grep` sweep:** the flag is never on disk in cleartext — only as
  ciphertext in `vault.enc`. The test asserts the flag and its body do not appear
  in any single file nor in a concatenated byte-sweep of the whole bundle.
- **Brute force:** the vault key is a 256-bit SHA-256 output; there is no
  shortcut but reconstructing the four tokens.
- **Image-library quirks:** the EXIF is standards-conformant (independently
  parses in Pillow during development), but the solver uses a self-contained
  stdlib parser, so solving needs no third-party package.
- **Gazetteer ambiguity:** landmarks are globally far apart and the EXIF jitter
  is sub-kilometre, so the nearest-neighbour match is never ambiguous; the solver
  also asserts a tight distance bound.


## Determinism / per-instance

`generate.py` derives the persona, landmark, metadata, serials, and the vault
key deterministically from `ZSCTF_SEED`; the flag comes from `ZSCTF_FLAG`. Same
seed → byte-identical bundle; different seed → a different persona and trail;
different flag → different ciphertext. All four properties are asserted by

