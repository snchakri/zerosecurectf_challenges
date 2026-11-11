with open("carrier_script.py", "r", encoding="utf-8") as f:
    text = f.read()

ZWSP = "\u200B"
ZWNJ = "\u200C"

bits = ""
for c in text:
    if c == ZWSP:
        bits += "0"
    elif c == ZWNJ:
        bits += "1"

bytes_list = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
flag = bytes(bytes_list).decode('utf-8')
print(flag)
