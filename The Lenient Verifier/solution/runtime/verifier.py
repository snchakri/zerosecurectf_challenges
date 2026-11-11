import hashlib
import json
import sys

ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

def verify_signature(message_bytes, sig_int, e, n):
    # Flawed PKCS#1 v1.5 verification logic (Bleichenbacher '06)
    decrypted = pow(sig_int, e, n).to_bytes(256, 'big')
    if not decrypted.startswith(b"\x00\x01\xff"):
        return False
    # Flawed parser: searches for ASN.1 magic anywhere after padding
    if ASN1_SHA1 not in decrypted:
        return False
    idx = decrypted.index(ASN1_SHA1) + len(ASN1_SHA1)
    received_hash = decrypted[idx:idx+20]
    expected_hash = hashlib.sha1(message_bytes).digest()
    return received_hash == expected_hash

# Modulus: 2048-bit composite (dummy verified key)
N = 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596230461
E = 3

if __name__ == "__main__":
    msg = b"admin_access_token_authorized_for_zerosecurectf"
    try:
        with open("submission_signature.hex", "r") as f:
            sig = int(f.read().strip(), 16)
        if verify_signature(msg, sig, E, N):
            print("ACCESS GRANTED: " + "zerosecure{bleichenbacher_e3_sig_forged_71a0}")
        else:
            print("INVALID SIGNATURE")
    except Exception as ex:
        print(f"ERROR: {ex}")
