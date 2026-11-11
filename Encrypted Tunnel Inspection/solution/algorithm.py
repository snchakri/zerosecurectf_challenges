with open("decrypted_http2_frame.txt", "r") as f:
    content = f.read()

import json
# Extract token
for line in content.splitlines():
    if "secret_token" in line:
        token = line.split('"secret_token": "')[-1].split('"')[0]
        print(token)
