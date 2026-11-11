"""decrypt.py (PUBLIC) - the Guard's token check. AES-CBC, no MAC.
Usage (server-side):  python decrypt.py <token_hex> <key_hex> <flag_file>
(The key is the Guard's; you never see it. You only submit a token.)"""
import sys
from Crypto.Cipher import AES
tok = bytes.fromhex(open(sys.argv[1]).read().strip()); key = bytes.fromhex(sys.argv[2])
iv, ct = tok[:16], tok[16:]
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
role_block = pt[16:32]                       # P1
if role_block[:13] == b"role=overlord":
    sys.stdout.buffer.write(b"HAIL " + open(sys.argv[3], "rb").read())
else:
    print("The Guard does not bow. role:", role_block[:13])
