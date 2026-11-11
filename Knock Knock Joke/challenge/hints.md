# Hints

1. Start by filtering for TCP handshake anomalies and look for one source host sending many SYN packets to closed ports.
2. Ignore payload extraction workflows. This challenge stores data in packet headers, not TCP stream data.
3. Focus on outbound SYN packets from the anomalous source. Capture the destination ports in order.
4. For each port in the signal stream, subtract `5000` and convert the result to ASCII.
