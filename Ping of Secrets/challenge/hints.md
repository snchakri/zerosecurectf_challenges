# Hints

Focus on outgoing ICMP Echo Requests rather than the Echo Replies.

The payloads hold encoded fragments: extract them in packet order, join, then decode. Filter: `icmp.type == 8`
