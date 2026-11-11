#!/usr/bin/env python3
from pathlib import Path
CHALLENGE=Path(__file__).resolve().parents[1]/"challenge"
import base64
text=(CHALLENGE/"data.txt").read_text().strip()
print(bytes.fromhex(base64.b64decode(text).decode()).decode())
