#!/usr/bin/env python3
from pathlib import Path
import re
from PIL import Image
HERE=Path(__file__).resolve().parent
image=Image.open(HERE/"unlocked/photo.png").convert("RGB")
bits=[channel & 1 for pixel in image.getdata() for channel in pixel]
for alignment in range(8):
    raw=bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(alignment,len(bits)-7,8))
    flag=re.search(rb"zerosecurectf\{[^}]+\}",raw)
    if flag:
        print(flag.group().decode());break
else:raise SystemExit("No flag in the RGB least-significant-bit stream")
