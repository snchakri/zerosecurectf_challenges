import os
import sys

BLOCK_SIZE = 16

def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE != 0:
        return False
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        return False
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return False
    return True

# Toy custom block cipher for reproducible sandbox environment without pycryptodome dependency
def toy_cipher_dec(block, key):
    # Invertible nonlinear permutation
    res = bytearray(16)
    for i in range(16):
        res[i] = ((block[i] ^ key[i % len(key)]) * 167 + 13) % 256
    return bytes(res)

def toy_cipher_enc(block, key):
    res = bytearray(16)
    for i in range(16):
        # Inverse of (x * 167 + 13) mod 256
        # 167 * 23 mod 256 = 1
        val = (block[i] - 13) % 256
        res[i] = ((val * 23) % 256) ^ key[i % len(key)]
    return bytes(res)

KEY = b"AUTHENTIC_SEC_KY"
SECRET_FLAG = b"zerosecure{cbc_padding_oracle_bitflip_02cf}"

def cbc_encrypt(plaintext, key, iv):
    padded = pkcs7_pad(plaintext)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = bytes([b ^ prev[j] for j, b in enumerate(block)])
        enc = toy_cipher_enc(xored, key)
        ciphertext += enc
        prev = enc
    return iv + ciphertext

def oracle(ct):
    if len(ct) < 32 or len(ct) % 16 != 0:
        return False
    iv = ct[:16]
    blocks = [ct[i:i+16] for i in range(16, len(ct), 16)]
    prev = iv
    for b in blocks:
        dec = toy_cipher_dec(b, KEY)
        plain_block = bytes([dec[j] ^ prev[j] for j in range(16)])
        prev = b
    # Check padding of last block
    return pkcs7_unpad(plain_block)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "get_ct":
        print(cbc_encrypt(SECRET_FLAG, KEY, b"INITIAL_VECT_123").hex())
    elif len(sys.argv) > 1 and sys.argv[1] == "oracle":
        ct = bytes.fromhex(sys.argv[2])
        print("VALID" if oracle(ct) else "INVALID")
