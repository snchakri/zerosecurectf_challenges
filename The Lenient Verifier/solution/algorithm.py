import hashlib
import math
import subprocess
import sys

ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
msg = b"admin_access_token_authorized_for_zerosecurectf"
h = hashlib.sha1(msg).digest()

prefix = b"\x00\x01\xff\x00" + ASN1_SHA1 + h
target = int.from_bytes(prefix + b"\x00" * (256 - len(prefix)), 'big')

lo = 0
hi = target
while lo < hi:
    mid = (lo + hi + 1) // 2
    if mid**3 <= target:
        lo = mid
    else:
        hi = mid - 1
sig = lo + 1

with open("submission_signature.hex", "w") as f:
    f.write(hex(sig)[2:])

res = subprocess.run([sys.executable, "verifier.py"], capture_output=True, text=True)
for line in res.stdout.splitlines():
    if "ACCESS GRANTED: " in line:
        print(line.split("ACCESS GRANTED: ")[-1].strip())
        sys.exit(0)
    elif "zerosecure{" in line:
        print(line.strip())
        sys.exit(0)
print(res.stdout)
