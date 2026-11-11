#!/usr/bin/env python3
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHALLENGE=HERE.parent/"challenge"
import subprocess
username="binary";argv0="./userpass"
weighted=sum(ord(c)*(i+1) for i,c in enumerate(username))
password=(weighted^(ord(username[0])*3))<<len(argv0)
result=subprocess.run([argv0,username,str(password)],cwd=CHALLENGE,capture_output=True,text=True,check=True)
print(result.stdout,end="")

