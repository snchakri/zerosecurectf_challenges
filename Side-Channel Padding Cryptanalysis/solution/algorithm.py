import sys
from oracle_service import oracle

# Direct algorithmic solve demonstrating byte-by-byte CBC padding oracle recovery
ct = bytes.fromhex(open("ciphertext.hex").read().strip())
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]

recovered_plaintext = b""

for block_idx in range(1, len(blocks)):
    prev_block = bytearray(blocks[block_idx - 1])
    curr_block = blocks[block_idx]
    
    intermediate = bytearray(16)
    recovered_block = bytearray(16)
    
    for byte_pos in range(15, -1, -1):
        pad_val = 16 - byte_pos
        test_block = bytearray(prev_block)
        
        # Set already recovered bytes to match desired pad_val
        for k in range(byte_pos + 1, 16):
            test_block[k] = intermediate[k] ^ pad_val
            
        found = False
        for guess in range(256):
            test_block[byte_pos] = guess
            if oracle(bytes(test_block) + curr_block):
                # Verify to avoid false pad
                if pad_val == 1 and byte_pos > 0:
                    test_block[byte_pos - 1] ^= 1
                    if not oracle(bytes(test_block) + curr_block):
                        continue
                intermediate[byte_pos] = guess ^ pad_val
                recovered_block[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                found = True
                break
        if not found:
            recovered_block[byte_pos] = 0
            
    recovered_plaintext += bytes(recovered_block)

# Strip PKCS7 padding
pad_len = recovered_plaintext[-1]
flag = recovered_plaintext[:-pad_len].decode('utf-8', errors='ignore')
print(flag)
