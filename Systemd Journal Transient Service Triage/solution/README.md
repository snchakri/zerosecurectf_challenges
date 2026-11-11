# Systemd Journal Transient Service Triage — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Systemd Journal Transient Service Triage (cgroup Environment Carving)


## 1. Vulnerability Analysis & Theoretical Foundations
Transient services (`systemd-run`) capture environment variables inside binary journal logs that persist after service termination.


## 2. Citations & Academic References
- Poettering, L. (2014). The systemd journal. systemd.io.
- Farmer, D., & Venema, W. (2005). Forensic Discovery.


## 3. Step-by-Step Walkthrough
1. Inspect `journal_slice.json`.
2. Locate trusted fields logged by journald daemon.
3. Extract the exported secret flag from the service environment.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{systemd_cgroup_environ_transient_leak_55da}
```


## 5. Defense Engineering & Remediation
Pass secrets to services via secure credentials storage (`LoadCredential=`) rather than environment variables.
