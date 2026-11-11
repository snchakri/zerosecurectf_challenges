ZeroSecure Beginner CTF Pack - Detailed Solutions
Bundle: /Users/sathwikareddy/Documents/CSI26/ZeroSecure_CTF7_Direct_Upload
Generated: 2026-04-17
Flag format: ZeroSecure_CTF{...}
This PDF is the only detailed writeup document for the upload bundle.
Challenge folders include metadata and player files only.
ZeroSecure site verification:
The official public challenge matrix on https://www.zerosecurectf.online/ lists Cryptography,
Web Security, Reverse Eng, Forensics, and OSINT.
The same site shows PLUS: 7GJQ+P44 in the LOCATION VECTOR section on April 17, 2026.
1. Staff Route (Web Security)
Flag: ZeroSecure_CTF{robots_txt_to_release_view}
Files: index.html, robots.txt, staff-only.html, app.js
Detailed solve path:
Open index.html. The page explicitly tells the player to start with robots.txt.
Open robots.txt and observe the disallowed route /staff-only.html.
Open staff-only.html. The page says the release dashboard depends on the URL view.
Inspect app.js. It reads the query parameter named view and unlocks the page only when
view=release.
Visit staff-only.html?view=release or reason it out from the script.
The page assembles data-piece attributes in order and prints the final flag.
2. Mirror Walk (Cryptography)
Flag: ZeroSecure_CTF{mirror_and_shift}
Files: index.html, note.txt, cipher.txt
Detailed solve path:
Read note.txt. It says: Three steps forward. Then stand in front of the mirror. What comes
back is the message.
The intended interpretation is Caesar shift by 3 and then Atbash mirror.
Take the ciphertext from cipher.txt: XsfiEsucfs_UDR{koffif_wjt_epord}
Apply the mirror first and then shift back by 3, or equivalently shift forward by 3 and then
mirror. The decoded result is ZeroSecure_CTF{mirror_and_shift}.
A quick verified route is Atbash(ciphertext) => ChurVhfxuh_FWI{pluuru_dqg_vkliw}, then Caesar
shift -3 => ZeroSecure_CTF{mirror_and_shift}.
3. USB Night Shift (Forensics)
Flag: ZeroSecure_CTF{nightshift_badge_roster}
Files: incident_auth.log, usb_audit.log, analyst_note.txt
Detailed solve path:
Read analyst_note.txt first. It says the suspicious access happened after the front desk login
and that the flag should combine the suspicious username and the more sensitive copied file.
Open incident_auth.log. The suspicious successful login is nightshift at 08:03:55, followed by
privilege escalation at 08:04:07.
Open usb_audit.log. The suspicious removable media is IRONKEY mounted by nightshift at

08:05:42.
Two files are copied after that, but badge_roster.csv is clearly the more sensitive file than
lobby_music.m3u.
Remove the extension and combine the values as instructed: nightshift + badge_roster.
Final flag: ZeroSecure_CTF{nightshift_badge_roster}.
4. Tiny Gate (Reverse Engineering)
Flag: ZeroSecure_CTF{mirror_then_xor}
Files: gate.py
Detailed solve path:
Read gate.py. The encode function reverses the candidate string, then for each byte adds i +
3, XORs the result with 0x2A, and compares against TARGET.
To solve it, reverse the transformation instead of brute forcing it.
For each TARGET byte at index i, compute ((byte XOR 0x2A) - i - 3) & 0xFF.
Convert the recovered byte list to text and reverse the full string at the end.
That produces ZeroSecure_CTF{mirror_then_xor}.
5. Signal Vector (OSINT)
Flag: ZeroSecure_CTF{7GJQ+P44}
Files: hint.txt
Detailed solve path:
Read hint.txt. It sends the player to the official ZeroSecure website and specifically points
to the LOCATION VECTOR section.
Open https://www.zerosecurectf.online/. In the public event information, the location section
lists MVSR ENGINEERING COLLEGE, HYDERABAD and shows PLUS: 7GJQ+P44.
Use the plus code as the flag body exactly as instructed.
Final flag: ZeroSecure_CTF{7GJQ+P44}.
Final verified answers:
1. ZeroSecure_CTF{robots_txt_to_release_view}
2. ZeroSecure_CTF{mirror_and_shift}
3. ZeroSecure_CTF{nightshift_badge_roster}
4. ZeroSecure_CTF{mirror_then_xor}
5. ZeroSecure_CTF{7GJQ+P44}