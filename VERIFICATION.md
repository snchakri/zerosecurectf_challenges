# Verification and source limitations

Prepared on 11 November 2026.

## Scope and checks

The scan inventoried 81,651 file paths across the local Documents and OneDrive Documents trees. The prior session recovered the final CTFd export and author source collections; this continuation reused that work, finished missing organization, and checked additional solvers.

All challenge directories contain exactly `challenge/` and `solution/`, both with a README. Every packaged file is included in `SHA256SUMS`. Checks looked for misplaced solution files and recognizable live cloud/GitHub/OAuth credentials; none were found in the selected publication files. Challenge flags, challenge cryptographic material, and fictional in-game credentials are intentionally retained on the solution side.

## Execution evidence

162 distinct reference commands completed with exit code zero. Prior-session main/medium results were reused for unchanged content; the three main-solver fixes, story solvers, packet solvers, and legacy wrappers were checked in the continuation. Exit code zero alone is not treated as proof of matching an event flag.

| Status | Challenges |
|---|---:|
| artifact flag derived; event answer differs or absent | 4 |
| author reference retained; not rerun | 40 |
| event/manual procedure | 8 |
| forged token generated; private verifier key absent | 1 |
| incomplete source | 20 |
| original mismatch | 1 |
| original source rebuilt | 3 |
| reference run completed | 156 |

See each `solution/verification.json` and `manifest.json` for the individual execution and known limitations.

## Confirmed incomplete source or mismatches

These items cannot honestly be described as fully reproduced from the available files:

- [RSA Broadcast](RSA%20Broadcast/solution/README.md): incomplete public handout: only author solver and hints found; solver constants are illustrative
- [Challenge 4: The Python Disassembly Puzzle](Challenge%204%20-%20%20The%20Python%20Disassembly%20Puzzle/solution/README.md): incomplete prototype: no generated transcript; original generator requires Python 3.9/3.10 and omits the global payload constant
- [MasterBaiter](MasterBaiter/solution/README.md): source/checker mismatch: accepted input reaches success branch but output differs from the author flag
- [Basic Web 1](Basic%20Web%201/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 10](Basic%20Web%2010/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 2](Basic%20Web%202/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 3](Basic%20Web%203/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 4](Basic%20Web%204/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 5](Basic%20Web%205/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 6](Basic%20Web%206/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 7](Basic%20Web%207/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 8](Basic%20Web%208/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [Basic Web 9](Basic%20Web%209/solution/README.md): incomplete historical HTML scaffold: no flag or complete author answer
- [HydraCore](HydraCore/solution/README.md): incomplete local archive: player narrative and link only; application source and full author solve were not found
- [StarkID](StarkID/solution/README.md): incomplete runtime: lib/keys, JWKS route, and key-generation script missing; full author exploit sketch preserved
- [Alexandria Mausoleum](Alexandria%20Mausoleum/solution/README.md): incomplete local runtime: original foundation document only
- [The Perfect Fake](The%20Perfect%20Fake/solution/README.md): incomplete author material: The loader/runtime and the vault encryption specification are absent from the preserved handout. The local archive contains the model and accepted answer, but no independently verified complete recovery procedure.
- [The Thirteenth Crossing](The%20Thirteenth%20Crossing/solution/README.md): incomplete author material: The residual cipher envelope and key derivation are not specified by the preserved handout. No complete author decoder was found locally. The unmatched record and accepted answer are preserved; decryption was not verified.
- [The Mask's Bell](The%20Mask%27s%20Bell/solution/README.md): incomplete author material: The sealed payload is preserved, but its key derivation, cipher mode, and serialization were not documented in the available author files. The registered answer is retained; a full independent decryption was not verified.
- [Crossed Signals](Crossed%20Signals/solution/README.md): incomplete author material: The player handout gives dependencies but omits the exact key derivation, nonce layout, and fragment envelope. No author implementation or complete writeup was found locally. The accepted answer is retained, but an independent artifact-to-flag solve was not verified.
- [The Hundred Steps](The%20Hundred%20Steps/solution/README.md): incomplete author material: The archive preserves the kernel and image, but no sector layout, key derivation, or extraction implementation. The cycle is reproducible; decoding the image to the accepted answer was not verified.

## Event-specific differences

- Several story artifacts derive a flag that differs from, or is absent in, the registered CTFd answer snapshot. Original accepted answers are preserved separately.
- The Doombot Token solver produces a CBC forgery; the Guard's original private key is unavailable, so the original server-side flag cannot be released locally.
- Physical activities and in-person flag hunts retain the actual event procedures and answers. They cannot be replayed by a file-only solver.
- Deliberate honeypots and decoy challenges retain their author analysis and the event scoring values.
- Oxbow's archived engine and image have different versions. The documented solver decodes the original v1 image directly.
- Python-version-specific bytecode and Windows-only binaries are preserved; instructions identify the required interpreter or available C-source alternative.

## Publication state

Automatic publication is stopped. An initial 123-challenge commit exists locally, but its push failed because native Git had no GitHub credentials. No remote publication is claimed. `scripts/publish.py` is available for a later authenticated push.
