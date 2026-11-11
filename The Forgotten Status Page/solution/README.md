# The Forgotten Status Page — solution

1. Open the capture in Wireshark and apply the `http` display filter.
2. Follow the relevant HTTP stream and inspect the server response body. The answer is transmitted as readable text.

Automated recovery from the original capture:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

Compare the derived result with `accepted_flags.txt`.
