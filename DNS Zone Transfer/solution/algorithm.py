with open("zone_transfer_axfr.txt", "r") as f:
    lines = f.readlines()

for line in lines:
    if "_secret IN TXT" in line:
        flag = line.split('"')[1]
        print(flag)
