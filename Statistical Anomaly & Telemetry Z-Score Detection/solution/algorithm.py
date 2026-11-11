with open("telemetry_data.csv", "r") as f:
    lines = f.readlines()

for line in lines[1:]:
    parts = line.strip().split(",")
    temp = float(parts[1])
    if temp > 100.0:
        print(parts[3])
