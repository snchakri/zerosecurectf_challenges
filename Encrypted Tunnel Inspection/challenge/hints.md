# Staged Hint Ladder: Encrypted Tunnel Inspection (TLS Key Log)

### Hint Level 1
Wireshark and automated DFIR parsers use the SSLKEYLOGFILE format to decrypt TLS sessions.

### Hint Level 2
Match the CLIENT_RANDOM value in the handshake with the keys in the key log.

### Hint Level 3
Inspect the decrypted HTTP/2 streams for administrative JSON responses.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
