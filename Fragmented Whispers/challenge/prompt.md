# Fragmented Whispers

The incident room calls it routine UDP chatter. You call it suspicious confetti: one conversation shattered into out-of-order scraps, with fake crumbs scattered to waste your time.

## Objective
Recover the hidden flag from the provided network capture.

## Provided Artifact
- `fragmented_whispers.pcap`

## Notes
- The intended signal is IPv4 fragmentation of one UDP datagram.
- Packet order is intentionally scrambled.
- Some fragments with the same Identification are decoys.
- Flag format: `ZeroSecure_CTF{...}`
