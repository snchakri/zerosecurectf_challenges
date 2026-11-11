with open("wireguard_session.log", "r") as f:
    lines = f.readlines()

for line in lines:
    if line.startswith("Data:"):
        hex_data = line.split("Data:")[-1].strip()
        flag = bytes.fromhex(hex_data).decode('utf-8')
        print(flag)
        break
