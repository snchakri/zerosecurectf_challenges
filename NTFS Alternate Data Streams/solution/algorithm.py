import json

with open("mft_record_1042.json", "r") as f:
    record = json.load(f)

for stream in record["streams"]:
    if stream["name"] == "payload.dat":
        print(stream["content"])
