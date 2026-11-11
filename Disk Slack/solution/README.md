# Disk Slack — solution

# DISK SLACK

**Category:** Forensics · **Difficulty:** ★★☆ (40–60m)

> A 64 KB disk image pulled from the bunker's duty terminal. Three people
> swear they saw a flag on it.


## Files
- `dist/evidence.img` — raw FAT12 image

A deleted file is only mostly gone. A live file doesn't fill its last cluster.
And empty space is rarely as empty as it looks. Three different hiding spots —
`fls`/`icat`, slack-space analysis, and unallocated-cluster carving all point
somewhere.

Flag format: `DOOM{...}`


## Suggested tooling
- The Sleuth Kit: `fls -r evidence.img`, `icat evidence.img <inode>`
- `blkls evidence.img` / slack extraction, or just a hex editor
- `strings evidence.img` (quick but noisy)


## Build
```
python build.py
```
Regenerates `dist/evidence.img` and self-verifies the deleted file, the slack
space, and the unallocated cluster.

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
