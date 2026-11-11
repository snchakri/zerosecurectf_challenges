import json

with open("docker_image_manifest.json", "r") as f:
    manifest = json.load(f)

for layer in manifest["layers"]:
    if "ENV SECRET_FLAG=" in layer["command"]:
        flag = layer["command"].split("ENV SECRET_FLAG=")[-1].strip()
        print(flag)
