import json

with open("journal_slice.json", "r") as f:
    data = json.load(f)

flag = data["CUSTOM_ENV_INJECTION"].split("EXPORTED_SECRET_FLAG=")[-1]
print(flag)
