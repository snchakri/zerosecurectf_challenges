import json

with open("dtmf_telephony.json", "r") as f:
    data = json.load(f)

flag = data["message"].split("authorizes token: ")[-1]
print(flag)
