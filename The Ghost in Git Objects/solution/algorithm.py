import json

with open("git_object_triage.json", "r") as f:
    data = json.load(f)

for line in data["diff"].splitlines():
    if "API_SECRET_KEY=zerosecure{" in line:
        flag = line.split("API_SECRET_KEY=")[-1].strip()
        print(flag)
