# solve.py -- ORGANIZER ONLY -- DO NOT DISTRIBUTE
#
# PHANTOM LEDGER -- Full solution
# Vulnerability: AES-CTR Nonce Reuse (Two-Time Pad)
#
# ROOT CAUSE:
#   server.py encrypt() uses nonce = DEPLOY_EPOCH (fixed) || _counter (module-global).
#   On process restart, Python re-imports the module: _counter resets to 0.
#   The relay crashed and rebooted a second time on March 21st.
#   Result: night1 and night2 both use nonce = DEPLOY_EPOCH || 0.
#   Same key + same nonce = same AES-CTR keystream = two-time pad.
#
#   night0 uses a different relay instance (different daily key) -- it is a
#   deliberate dead end to test whether contestants read the infrastructure notes.
#
# SOLVE PATH:
#   1. XOR pairs: night0^night1 = random. night1^night2 = 36 leading zero bytes.
#   2. Known plaintext (26 bytes): XOR ct1 with header -> 26 bytes of keystream.
#   3. Crib drag: relay_diagnostic.txt shows format. Extend keystream iteratively.
#   4. Decode: extract base64 blob from night2, digit sum of date, XOR -> FLAG.
#
# UNINTENDED SOLVE PATHS:
#   - Brute force AES key: infeasible (128-bit key)
#   - night0 attack: uses different daily key -- XOR with night1/night2 = noise

import base64

print("=" * 60)
print("PHANTOM LEDGER -- Solution")
print("=" * 60)

ct0 = open('night0.bin', 'rb').read()
ct1 = open('night1.bin', 'rb').read()
ct2 = open('night2.bin', 'rb').read()
print(f"\n[*] Loaded: night0={len(ct0)}B  night1={len(ct1)}B  night2={len(ct2)}B")

# Step 1: XOR pair analysis
print("\n[Step 1] XOR pair analysis -- detect nonce reuse")

def count_leading_zeros(a, b):
    xored = bytes(x ^ y for x, y in zip(a, b))
    count = 0
    for byte in xored:
        if byte == 0:
            count += 1
        else:
            break
    return count

lz_01 = count_leading_zeros(ct0, ct1)
lz_12 = count_leading_zeros(ct1, ct2)
print(f"  night0 ^ night1 : {lz_01:>3} leading zero bytes  (different daily key -> noise)")
print(f"  night1 ^ night2 : {lz_12:>3} leading zero bytes  *** NONCE REUSE CONFIRMED ***")
assert lz_12 > 20, "night1^night2 should show many leading zeros"
assert lz_01 < 5,  "night0^night1 should be noise (different key)"

# Step 2: Known-plaintext keystream recovery
print("\n[Step 2] Known-plaintext attack -- recover keystream")

KNOWN_HEADER = b"PHANTOM-LEDGER // GHOST // "   # 26 bytes from README

ks = bytearray(max(len(ct1), len(ct2)))
for i, k in enumerate(KNOWN_HEADER):
    ks[i] = ct1[i] ^ k

recovered_from_ct2 = bytes(ct2[i] ^ ks[i] for i in range(len(KNOWN_HEADER)))
assert recovered_from_ct2 == KNOWN_HEADER, "Keystream recovery failed"
print(f"  Known header applied to ct2: {recovered_from_ct2!r}")
print(f"  Header matches [OK]  -- nonce reuse confirmed")

# Step 3: Crib dragging
print("\n[Step 3] Crib dragging -- extend keystream using night1 format")
print("         (relay_diagnostic.txt reveals: DATE // STATUS // NOTES // --G)")

FULL_PT1 = (
    b"PHANTOM-LEDGER // GHOST // 2024-03-20 // "
    b"Nothing to report. Swept the floor, all green. "
    b"Watchdogs quiet. No positions flagged. "
    b"Encrypted comms nominal. Running final integrity check. "
    b"Signing off clean. --G"
)

def pkcs7_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n] * n)

pt1_padded = pkcs7_pad(FULL_PT1)
for i in range(len(ct1)):
    ks[i] = ct1[i] ^ pt1_padded[i]

print()
regions = [
    (0,   26,  "shared prefix (known header)"),
    (26,  36,  "shared date prefix (identical in both: ' 2024-03-2', xor12=0x00)"),
    (36,  55,  "date divergence + status field start"),
    (55,  90,  "status / notes field"),
    (90,  130, "notes continues"),
    (130, len(ct2), "tail + base64 blob"),
]
for start, end, label in regions:
    end = min(end, len(ct2))
    chunk = bytes(ct2[i] ^ ks[i] for i in range(start, end))
    print(f"  bytes {start:>3}-{end-1:>3}  [{label}]: {chunk!r}")

# Step 4: Extract and decode
print("\n[Step 4] Package decode")

pt2 = bytes(ct2[i] ^ ks[i] for i in range(len(ct2)))
print(f"\n  Night2 plaintext:\n  {pt2.rstrip()!r}\n")

blob_start = pt2.index(b"Decode: ") + len(b"Decode: ")
blob_end   = pt2.index(b" --G")
b64_blob   = pt2[blob_start:blob_end]
print(f"  Base64 blob: {b64_blob.decode()}")

raw = base64.b64decode(b64_blob)
print(f"  Raw bytes:   {raw.hex()}")
print(f"  Raw (text):  {raw.decode('latin-1')!r}  <- not yet the flag")

date_pos  = pt2.index(b"2024-03-")
date_str  = pt2[date_pos:date_pos + 10].decode()
digit_sum = sum(int(c) for c in date_str if c.isdigit())
print(f"\n  Date found:  {date_str}")
print(f"  Digit sum:   {' + '.join(c for c in date_str if c.isdigit())} = {digit_sum}")
print(f"  Hint source: server.py comment -- 'packages are keyed to the session date'")

flag = bytes(b ^ digit_sum for b in raw)
print(f"\n[+] FLAG: {flag.decode()}")
