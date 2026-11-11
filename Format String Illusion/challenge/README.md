# Format String Illusion

**Category:** Cryptography

# Format String Illusion

## Story
An incident-response export from a backend cluster looks like routine failure logs.
A teammate insists the attacker hid data in the formatting itself, not the literal words.

## Your Task
Inspect `challenge.txt` and recover the hidden flag.
The payload is disguised as noisy server logs, but the capitalization pattern of letters carries the real ciphertext.

## Rules
- Keep only alphabetic characters (`A-Z` and `a-z`) in their original order.
- Use case as a two-state signal.
- Split the signal into groups of 5 and decode with a Baconian mapping.
- Submit only the final flag.
- Flag format is: `ZeroSecure_CTF{...}`
- Keep exact characters (case-sensitive).

Good luck.

[2026-04-17 03:17:54] AUtH.gAtewAy WARn Fmt_HANDLER rEJectEd tokEN iD=9031 sOUrce=API-cOrE LATenCy=183MS reTrY=0 traCe=AA31
[2026-04-17 03:17:55] NEt.ProXy ErroR cHEcKSuM DrIFT On miRRor-B q
[2026-04-17 03:19:57] 503 503 503 :: ---
99
1456
504
25
3570
879
52
9841
458
15
9370
726
32
1063
482
59
8795
962
74
8391
794
47
6951
943
27
8409
786
83
