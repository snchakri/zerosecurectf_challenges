# Whispers in the Void - Beginner Step-by-Step Solution

This guide explains the solve path like you are doing this for the first time.

## 0. What you get

From the participant package, you need only these files:

1. `whispers_in_the_void.pcap`
2. `challenge.txt`

Ignore `deadends.txt` for solving. It is there to distract you.

## 1. Setup once

Open a terminal in the challenge folder and install dependencies:

python -m pip install -r requirements.txt

## 2. Read the challenge prompt

Open `deliverables/participant/challenge.txt`.

It tells you the flag format is:

zerosecurectf{...}

## 3. Solve like a participant (single command)

Run:

python scripts/noob_participant_solve.py

The script prints each stage in plain language:

1. Load PCAP.
2. Find the strongest bit-like TCP flow.
3. Rebuild PNG bytes from packet bit payloads.
4. Extract hidden AES payload from image parity.
5. Recover AES key from repeating timing pattern.
6. Decrypt and print the flag.

## 4. What the script is doing, in simple words

### Step A: Find the right traffic stream

The script scans packets and finds TCP packets that carry exactly one byte payload: `0` or `1`.

It counts these by tuple:

(source IP, destination IP, source port, destination port)

The tuple with the largest count is chosen as the hidden carrier stream.

### Step B: Convert packet bits into bytes

Each packet contributes one bit.

Group every 8 bits into one byte. The resulting byte stream should start with PNG signature:

89 50 4E 47 0D 0A 1A 0A

If yes, you recovered the image.

### Step C: Read hidden payload from image

The image is grayscale.

Take pixels in pairs. For each pair, compute:

abs(p0 - p1) mod 2

That gives one hidden bit.

First 16 bits tell payload length.

Remaining bits form payload bytes:

IV (16 bytes) + AES ciphertext.

### Step D: Recover the key from timing

Take packet timestamps and convert to microseconds.

Compute inter-packet delays.

Group delays by index mod 256.

Each group corresponds to one key bit repeated many times.

Average each group and split into low/high clusters to recover 256 bits.

Convert bits to 32-byte AES key.

### Step E: Decrypt

Use AES-CBC with recovered key and IV.

Decrypt ciphertext, remove PKCS#7 padding, decode UTF-8 string.

You get the flag.

## 5. Expected successful output

You should see lines like:

1. Loaded packets: 3600
2. Candidate flow ... with around 3168 bit packets
3. PNG size around 396 bytes
4. Recovered key bytes: 32
5. Flag: zerosecurectf{the_real_deadend}

## 6. Common beginner mistakes

1. Using all packets instead of filtering to one tuple.
2. Forgetting that bits must be grouped in chunks of 8.
3. Not using modulo-256 grouping for timing analysis.
4. Trying random brute-force decryption before recovering timing key.

## 7. Quick verification

If you want to validate bundle integrity as organizer:

python verify_challenge.py --bundle deliverables

But for participant solve demonstration, use:

python scripts/noob_participant_solve.py
