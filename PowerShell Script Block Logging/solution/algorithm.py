import json

with open("powershell_4104.json", "r") as f:
    ev = json.load(f)

msg = ev["Message"]
flag = msg.split("$SecretAuthKey = '")[-1].split("'")[0]
print(flag)
