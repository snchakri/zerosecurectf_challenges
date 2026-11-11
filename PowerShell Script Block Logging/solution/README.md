# PowerShell Script Block Logging — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: PowerShell Script Block Logging (Windows Event 4104)


## 1. Vulnerability Analysis & Theoretical Foundations
Windows Script Block Logging (Event ID 4104) captures the full un-obfuscated content of executed PowerShell code, frustrating adversarial attempts to hide commands behind complex encoders or download cradles.


## 2. Citations & Academic References
- Microsoft Learn (2022). About Script Block Logging.
- Mandiant (2021). De-obfuscating PowerShell Invocations with Event Logs.


## 3. Step-by-Step Walkthrough
1. Parse `powershell_4104.json` extracted from the operational event log.
2. Inspect the logged `ScriptBlock text` field.
3. Extract the plaintext `$SecretAuthKey` variable initialization.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{event_4104_powershell_scriptblock_83a1}
```


## 5. Defense Engineering & Remediation
Forward Event ID 4104 to centralized SIEM systems and maintain restrictive PowerShell Constrained Language Mode (CLM).
