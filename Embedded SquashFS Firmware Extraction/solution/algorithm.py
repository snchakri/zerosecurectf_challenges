import json

with open("firmware_fs.json", "r") as f:
    data = json.load(f)

for f in data["recovered_files"]:
    if f["path"] == "/etc/shadow.bak":
        print(f["content"].split(":")[1])
