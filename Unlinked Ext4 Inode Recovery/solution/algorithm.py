with open("fs_chunk.img", "rb") as f:
    data = f.read()

# Scan for ext4 unlinked extent payload containing flag format
idx = data.find(b"zerosecure{")
if idx != -1:
    end = data.find(b"}", idx)
    flag = data[idx:end+1].decode('utf-8')
    print(flag)
