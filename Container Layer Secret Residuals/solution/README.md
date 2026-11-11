# Container Layer Secret Residuals — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Container Layer Secret Residuals (Docker Multi-Stage Diffing)


## 1. Vulnerability Analysis & Theoretical Foundations
Docker image layers are immutable. Setting an environment variable or copying a secret in an early build layer persists the data permanently in that layer's tar archive, even if removed in subsequent layers.


## 2. Citations & Academic References
- Docker Inc. (2022). Docker Image Specification v1.2.
- National Cyber Security Centre (NCSC). Container Security Guidelines.


## 3. Step-by-Step Walkthrough
1. Inspect `docker_image_manifest.json` layer history.
2. Review intermediate layer build commands for `ENV SECRET_FLAG=` declarations.
3. Extract the residual credential string from the cached layer.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{docker_intermediate_layer_diff_63c2}
```


## 5. Defense Engineering & Remediation
Use Docker BuildKit secrets mounting (`--mount=type=secret`) or multi-stage builds where secrets never enter build context layers.
