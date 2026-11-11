import json

with open("archive_audit.json", "r") as f:
    data = json.load(f)

for entry in data["entries"]:
    if "../" in entry["filename"]:
        content = entry["content"]
        flag = content.split("# Flag: ")[-1].splitlines()[0]
        print(flag)
