#!/usr/bin/env python3
from pathlib import Path
CHALLENGE=Path(__file__).resolve().parents[1]/"challenge"
import re
b=(CHALLENGE/"asset.png").read_bytes()
for m in re.findall(rb"ZeroSecure_CTF\{[^}]+\}",b):print(m.decode())
