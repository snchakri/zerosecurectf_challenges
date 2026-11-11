# The Careless Admin — solution

1. Apply the `http.authorization` Wireshark filter.
2. Copy the bytes after `Authorization: Basic ` and Base64-decode them. Base64 provides no confidentiality. The decoded value is the answer.

Automated recovery from the original capture:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

Compare the derived result with `accepted_flags.txt`.
