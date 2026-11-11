import sys
import subprocess

N = 7023800552605391553069181779541565402906444708994054338197061016196541057555761362404843897272895418200576507768686790538954611993496044816642965824017549
E = 65537

target_msg = "ADMIN_AUTH_TOKEN_LEVEL_9"
m = int.from_bytes(target_msg.encode('utf-8'), 'big')

r = 1337420
blinded_m = (m * pow(r, E, N)) % N

res = subprocess.run([sys.executable, "blind_signer.py", "sign", str(blinded_m)], capture_output=True, text=True)
blinded_sig = int(res.stdout.strip())

r_inv = pow(r, -1, N)
sig = (blinded_sig * r_inv) % N

res2 = subprocess.run([sys.executable, "blind_signer.py", "verify", target_msg, str(sig)], capture_output=True, text=True)
output = res2.stdout.strip()
if "ACCESS GRANTED: " in output:
    print(output.split("ACCESS GRANTED: ")[-1])
else:
    print(output)
