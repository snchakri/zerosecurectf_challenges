# DNS Zone Transfer — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: DNS Zone Transfer (AXFR) Record Audit (Information Disclosure)


## 1. Vulnerability Analysis & Theoretical Foundations
Misconfigured DNS nameservers permitting unrestricted AXFR transfers leak entire internal domain topologies, including TXT records containing credentials.


## 2. Citations & Academic References
- RFC 5936 (2010). DNS Zone Transfer Protocol (AXFR).
- Albitz, P., & Liu, C. (2001). DNS and BIND. O'Reilly.


## 3. Step-by-Step Walkthrough
1. Review dumped zone file `zone_transfer_axfr.txt`.
2. Audit resource records for `_secret` TXT entries.
3. Extract the flag stored within the TXT record.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{dns_axfr_zone_file_loc_and_txt_88ef}
```


## 5. Defense Engineering & Remediation
Restrict AXFR zone transfers strictly to authorized secondary nameserver IP addresses.
