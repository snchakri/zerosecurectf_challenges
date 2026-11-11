# Hints

1. Start with ICMP Echo Request filtering and compare header fields between packets.
2. The useful packets share one constant ICMP header value; decoys do not.
3. Extract only one payload byte per signal packet (same offset every time), rebuild a binary file, then open it as ZIP.
