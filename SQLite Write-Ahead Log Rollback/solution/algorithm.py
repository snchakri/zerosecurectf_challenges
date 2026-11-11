import json

with open("sqlite_wal_audit.json", "r") as f:
    data = json.load(f)

for frame in data["wal_frames"]:
    if "ROLLED_BACK" in frame["status"]:
        line = frame["data"]
        flag = line.split("', '")[-1].split("');")[0]
        print(flag)
