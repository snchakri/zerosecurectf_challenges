import json

with open("kerberos_asrep.json", "r") as f:
    data = json.load(f)

cipher = data["enc_part"]["cipher"]
flag = cipher.split(":")[-1]
print(flag)
