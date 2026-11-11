# Carved Polyglot — solution

# CARVED POLYGLOT

**Category:** Forensics · **Difficulty:** ★★☆ (30–45m)

> A photo of the bunker. That's all. Probably.


## Files
- `dist/bunker_photo.png` — a bunker photo (and then some)

The file opens fine as an image. But `file`, `binwalk`, and a quick look at the
tail suggest it didn't stop where a PNG should. Carve what's appended. When you
hit a locked archive, the password is weak — a wordlist will do.

Flag format: `DOOM{...}`


## Build
```
python build.py          # needs: Pillow  (zipcrypto.py is bundled, no extra deps)
```
Regenerates `dist/bunker_photo.png` and self-verifies the PNG, the appended ZIP,
the egg in the archive comment, and the encrypted inner archive.

> Author note: the inner archive uses traditional ZipCrypto with password
> `trustno1` (present in rockyou), crackable with `fcrackzip -D -p rockyou.txt`
> or `zip2john` + `john`.

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
