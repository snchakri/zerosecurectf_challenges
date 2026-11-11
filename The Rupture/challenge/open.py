"""open.py - lift a station's gate with the narrative answer.
Usage:  python open.py gate.bin "<your answer>"
The answer is normalized to lowercase letters/digits (spaces and punctuation ignored).
On the right answer the handout files are written into this folder; a wrong answer is rebuffed."""
import sys, io, re, hashlib, zipfile
from pathlib import Path
from Crypto.Cipher import AES
MAGIC = b"INCURSION-GATE1\n"
def norm(a): return re.sub(r"[^a-z0-9]", "", a.lower())
blob = Path(sys.argv[1]).read_bytes(); answer = " ".join(sys.argv[2:])
station = '15_the_rupture'
salt = blob[3:11]; nonce = hashlib.sha256(b"nonce|"+salt).digest()[:8]
key = hashlib.sha256(b"incursion-gate|"+station.encode()+b"|"+norm(answer).encode()+b"|"+salt).digest()[:16]
pt = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(blob[11:])
if pt[:len(MAGIC)] != MAGIC:
    print("The gate does not move. That is not the name he carries. Read the Dossier again."); sys.exit(1)
with zipfile.ZipFile(io.BytesIO(pt[len(MAGIC):])) as z:
    z.extractall("."); print("The gate opens. Rendered:", ", ".join(z.namelist()))
