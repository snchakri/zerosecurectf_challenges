# Hints

1. Group candidate packets by IPv4 `Identification`, source, destination, and protocol before trusting payload bytes.
2. IPv4 `Fragment Offset` is in units of 8 bytes, not raw bytes.
3. Overlap decoys exist. Validate IPv4 header checksums and avoid mixing mathematically invalid fragments into your reconstruction.
4. Reassemble the UDP datagram bytes, strip the UDP header, then treat the remaining bytes as a ZIP archive.
