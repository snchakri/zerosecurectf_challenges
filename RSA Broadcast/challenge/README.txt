ZeroSecure CTF 2024 — Broadcast Challenge
==========================================
Prepared for: CTF organizers

Folder structure
----------------
zerosecure_ctf/
├── broadcast.zip          ← Distribute this to participants
│   └── challenge_dist/
│       ├── README.txt
│       └── challenge.py
│
├── solver_hints/          ← Organizer-only (do NOT distribute)
│   ├── hints.txt          ← 3 progressive hints (with suggested point costs)
│   └── solver.py          ← Full working exploit (requires: pip install sympy)
│
└── README.txt             ← This file

Deployment notes
----------------
1. Give participants only `broadcast.zip`.
2. Release hints.txt hints one at a time through your CTF platform
   (e.g. CTFd) as teams request them.
3. Run solver.py on your own machine to verify the flag before the event.

Flag
----
ZeroSecure_ctf{hastad_br04dcast_3=3}

Category  : Cryptography
Difficulty: Medium
Points    : 100 (suggested)
Author    : ZeroSecure

Vulnerability
-------------
Håstad's Broadcast Attack.
RSA with e=3, no padding, same plaintext sent to 3 recipients.
Chinese Remainder Theorem + integer cube root = full plaintext recovery.
