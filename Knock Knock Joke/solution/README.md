# ch4_knock_knock_joke — solution

Run commands from this challenge directory unless the retained author instructions specify another working directory.

1. Open the packet capture in Wireshark and apply the protocol filter named in the player prompt.
2. Recover the channel bytes in packet/sequence order using the documented encoding.
3. Run the reference solver in `solution/tools/` with `--pcap challenge/<capture>.pcap`; inspect `--help` for any challenge-specific options.
4. Compare with the retained expected answer in `solution/internal/`.

**Verification:** archived reference; not rerun. Original event-only links may no longer respond.

## Runnable recovery

The wrapper passes the packaged capture to the original reference decoder. Rogue Edge Sensor also requires `tshark` on PATH; the other capture decoders use their original Python parser. Temporary reconstruction files stay outside the player folder.

```bash
python solution/solve.py
```
