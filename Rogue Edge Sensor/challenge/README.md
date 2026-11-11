# ch1_rogue_edge_sensor

**Category:** Network Forensics

# Rogue Edge Sensor

Campus Facilities flagged unusual chatter from a smart temperature sensor cluster in the main hall. Traffic looks normal at first glance, but incident response suspects covert telemetry abuse.

## Objective
Recover the hidden flag from the provided network capture.

## Provided Artifact
- `rogue_edge_sensor.pcap`

## Notes
- The capture includes MQTT traffic from multiple sensors.
- Normal building telemetry is mixed in intentionally.
- Flag format: `ZeroSecure_CTF{...}`

