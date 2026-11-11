# Noise Protocol Tunnel Triage — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Noise Protocol Tunnel Triage (WireGuard Traffic Analysis)


## 1. Vulnerability Analysis & Theoretical Foundations
WireGuard utilizes the Noise_IKpsk2 protocol handshake over UDP. When a pre-shared key (PSK) and ephemeral keys are compromised or extracted from host memory, the entire session transport stream can be decrypted using ChaCha20-Poly1305 AEAD.


## 2. Citations & Academic References
- Donenfeld, J. A. (2017). WireGuard: Next Generation Kernel Network Tunnel. NDSS 2017.
- Perrin, T. (2018). The Noise Protocol Framework.


## 3. Step-by-Step Walkthrough
1. Parse `wireguard_session.log` to identify interface public keys and pre-shared key (PSK).
2. Locate the Transport Data payload packet (type 0x04).
3. Decode hexadecimal byte string representing decrypted plaintext transport stream.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{wireguard_preshared_key_tunnel_09ab}
```


## 5. Defense Engineering & Remediation
Securely store private keys in hardware TPM/HSM enclaves and rotate pre-shared keys frequently.
