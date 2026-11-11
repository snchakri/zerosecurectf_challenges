# Ping Pong Exfiltration

The smart thermostat in Main Hall insists it is just doing routine heartbeat pings, and honestly it sounds very convincing. Unfortunately, one tiny byte in each "totally normal" ping is spilling secrets like a cafeteria gossip champion.

## Objective
Recover the hidden flag from the provided network capture.

## Provided Artifact
- `ping_pong_exfiltration.pcap`

## Notes
- Traffic contains ICMP Echo Request and Echo Reply noise.
- Signal packets are mixed with decoys by design.
- The hidden data reconstructs a ZIP archive before revealing the final flag.
- Flag format: `ZeroSecure_CTF{...}`
