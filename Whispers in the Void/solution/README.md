# Whispers in the Void — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Analyze the packet timing and select the covert flow.
2. Reconstruct the embedded image from that flow.
3. Extract the PVD steganographic bitstream and decode the flag according to the author walkthrough.

Author procedures and reference material:

- [organizer/docs/solution_walkthrough.md](organizer/docs/solution_walkthrough.md)

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

The reference procedure identifies the TCP bit stream, rebuilds its PNG, extracts the PVD payload, recovers the AES key from timing buckets, then decrypts the flag. The wrapper supplies the correct packaged PCAP path.

```bash
python solution/solve.py
```
