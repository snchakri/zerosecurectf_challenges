# Ping of Secrets — solution

1. Filter for ICMP Echo Requests with `icmp.type == 8`; ignore reflected replies.
2. Select request sequence numbers 1, 2, and 3. Concatenate their Base64 payload fragments in sequence order, then decode once.

Automated recovery from the original capture:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

Compare the derived result with `accepted_flags.txt`.
