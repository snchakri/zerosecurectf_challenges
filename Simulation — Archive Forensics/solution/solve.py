#!/usr/bin/env python3
from pathlib import Path
import zipfile,re,base64,codecs
archive=next((Path(__file__).resolve().parents[1]/"challenge").glob("*.zip"))
with zipfile.ZipFile(archive) as z:
    matches=[n for n in z.namelist() if n.endswith("artifact_0042.txt") and "bundle" in n.lower()]
    for name in matches:
        text=z.read(name).decode(errors="replace")
        for token in re.findall(r"::\s*([A-Za-z0-9+/=]+)",text):
            try:value=codecs.decode(base64.b64decode(token).decode(),"rot_13")
            except (ValueError,UnicodeError):continue
            if "zerosecurectf{simulation_flag}" in value:print(value)
