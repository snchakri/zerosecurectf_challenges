# NTFS Alternate Data Streams — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: NTFS Alternate Data Streams (ADS Forensic Recovery)


## 1. Vulnerability Analysis & Theoretical Foundations
NTFS allows multiple data streams associated with a single file descriptor. Threat actors hide payloads and tools in Alternate Data Streams (`file:stream`), which remain invisible to standard command-line directory listings.


## 2. Citations & Academic References
- Metz, J. (2010). NTFS analysis: Master File Table and Alternate Data Streams.
- SANS Institute (2019). Forensic Analysis of NTFS Artifacts.


## 3. Step-by-Step Walkthrough
1. Examine `mft_record_1042.json` containing attributes for `quarterly_budget.xlsx`.
2. Locate the non-standard `$DATA` attribute named `payload.dat`.
3. Extract the resident stream content to recover the hidden flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{ntfs_alternate_data_stream_zone_4210}
```


## 5. Defense Engineering & Remediation
Deploy EDR agents configured to monitor and log NTFS Alternate Data Stream creation and execution.
