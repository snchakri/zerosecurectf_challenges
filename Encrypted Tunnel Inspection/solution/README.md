# Encrypted Tunnel Inspection — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Encrypted Tunnel Inspection (TLS Key Log Decryption)


## 1. Vulnerability Analysis & Theoretical Foundations
TLS 1.3 sessions using forward-secret Ephemeral Diffie-Hellman can be completely decrypted if client/server processes export the NSS SSLKEYLOGFILE master secrets.


## 2. Citations & Academic References
- RFC 8446 (2018). The Transport Layer Security (TLS) Protocol Version 1.3.
- Wireshark Foundation (2020). TLS Decryption documentation.


## 3. Step-by-Step Walkthrough
1. Correlate client random hashes in `sslkeylog.txt` with session traffic.
2. Decrypt HTTP/2 frame streams.
3. Parse the administrative JSON authorization response containing the secret flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{sslkeylog_master_secret_decrypted_11bc}
```


## 5. Defense Engineering & Remediation
Enforce strict endpoint controls preventing unauthorized environment variables (SSLKEYLOGFILE) from being set in production services.
