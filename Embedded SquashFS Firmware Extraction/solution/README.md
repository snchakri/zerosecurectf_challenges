# Embedded SquashFS Firmware Extraction — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Embedded SquashFS Firmware Extraction (Backup File Triage)


## 1. Vulnerability Analysis & Theoretical Foundations
IoT firmware images frequently bundle Linux root filesystems compressed with SquashFS. System administrators or setup scripts often leave un-sanitized backup files (`/etc/shadow.bak`) containing sensitive hashes or plaintext keys.


## 2. Citations & Academic References
- Heffner, C. (2011). Reverse Engineering Embedded Firmware. DEF CON 19.
- Costin, A., et al. (2014). A Large-Scale Analysis of the Security of Embedded Firmwares. USENIX Security 2014.


## 3. Step-by-Step Walkthrough
1. Review extracted SquashFS filesystem records in `firmware_fs.json`.
2. Locate backup file `/etc/shadow.bak`.
3. Extract the credential string preserved in the backup shadow file.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{squashfs_shadow_backup_recovery_77fe}
```


## 5. Defense Engineering & Remediation
Sanitize build directories before firmware packaging and apply automated firmware analysis tools (Binwalk, FACT) in CI/CD pipelines.
