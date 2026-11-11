#!/usr/bin/env python3
from pathlib import Path
import re,subprocess
challenge=Path(__file__).resolve().parents[1]/"challenge"
text=(challenge/"tiny_lock").read_text()
parts=dict(re.findall(r'^p(\d+)="([^"\n]*)"',text,re.M))
flag="".join(parts[i] for i in sorted(parts,key=int))
if not re.fullmatch(r"ZeroSecure_CTF\{[^}]+\}",flag):raise SystemExit("No reconstructed flag")
result=subprocess.run(["sh",str(challenge/"tiny_lock")],input=flag+"\n",capture_output=True,text=True,check=True)
if "Correct!" not in result.stdout:raise SystemExit("Checker rejected recovered input")
print(flag)
