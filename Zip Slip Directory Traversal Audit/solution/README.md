# Zip Slip Directory Traversal Audit — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Zip Slip Directory Traversal Audit (Path Traversal Vulnerability)


## 1. Vulnerability Analysis & Theoretical Foundations
Archive extractors failing to validate member file paths against directory traversal sequences (`../`) overwrite arbitrary files on the host filesystem.


## 2. Citations & Academic References
- Snyk Research (2018). Zip Slip Vulnerability.
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory.


## 3. Step-by-Step Walkthrough
1. Analyze archive metadata in `archive_audit.json`.
2. Locate entry targeting relative directory `../../../../etc/cron.d/`.
3. Extract the flag embedded in the malicious archive member.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{zip_slip_path_traversal_symlink_72cd}
```


## 5. Defense Engineering & Remediation
Canonicalize destination paths before extraction and verify that paths start with the target directory.
