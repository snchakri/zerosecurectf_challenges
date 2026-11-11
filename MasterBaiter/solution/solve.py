#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import itertools,subprocess
for chars in itertools.product(range(33,127),repeat=3):
    if sum(c*(i+1) for i,c in enumerate(chars))%1337==420:
        candidate=bytes(chars).decode();break
result=subprocess.run(["./masterbaiter"],input=candidate+"\n",cwd=CHALLENGE,capture_output=True,text=True,check=True,timeout=15)
print("Accepted input:",repr(candidate));print(result.stdout,end="")

