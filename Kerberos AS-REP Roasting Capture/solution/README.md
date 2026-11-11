# Kerberos AS-REP Roasting Capture — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Kerberos AS-REP Roasting Capture (etype 23 Ticket Extraction)


## 1. Vulnerability Analysis & Theoretical Foundations
When an Active Directory user account has 'Do not require Kerberos preauthentication' configured, any domain entity can request a KRB-AS-REP ticket containing a section encrypted with the user's RC4-HMAC (etype 23) password hash.


## 2. Citations & Academic References
- Metcalf, S. (2015). Kerberos & Attacks Against Active Directory. BSides Charm.
- RFC 4120 (2005). The Kerberos Network Authentication Service (V5).


## 3. Step-by-Step Walkthrough
1. Examine `kerberos_asrep.json` for packet message type 11 (KRB-AS-REP).
2. Locate `enc_part` utilizing encryption type 23 (RC4-HMAC).
3. Extract the Kerberos hash string formatted for offline password cracking.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{asrep_roast_etype23_hash_carved_31ac}
```


## 5. Defense Engineering & Remediation
Enforce Kerberos pre-authentication on all domain user accounts and ensure passwords possess sufficient entropy against offline hash cracking.
