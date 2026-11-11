#!/usr/bin/env python3
from pathlib import Path
import re,base64
text=(Path(__file__).resolve().parents[1]/"challenge/main.js").read_text()
for encoded in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}",text):
    try:decoded=base64.b64decode(encoded).decode()
    except (ValueError,UnicodeError):continue
    if re.fullmatch(r"ZeroSecure_CTF\{[^}]+\}",decoded):print(decoded)
