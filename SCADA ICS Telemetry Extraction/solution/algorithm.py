import json
import struct

with open("scada_modbus_traffic.json", "r") as f:
    data = json.load(f)

regs = [int(x, 16) for x in data["registers_hex"]]
byte_stream = b"".join(struct.pack(">H", r) for r in regs).rstrip(b"\x00")
print(byte_stream.decode('utf-8'))
