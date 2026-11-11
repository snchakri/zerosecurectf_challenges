import json

with open("icmp_timing_trace.json", "r") as f:
    packets = json.load(f)

bits = ""
for p in packets:
    if p["delta_ms"] > 300:
        bits += "1"
    else:
        bits += "0"

chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
print("".join(chars))
