# Statistical Anomaly & Telemetry Z-Score Detection — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Statistical Anomaly & Telemetry Z-Score Detection (Outlier Analysis)


## 1. Vulnerability Analysis & Theoretical Foundations
Steganographic data hidden within large continuous numerical sensor telemetry can be detected by statistical Z-score outlier filtering.


## 2. Citations & Academic References
- Chandola, V., et al. (2009). Anomaly detection: A survey. ACM CSUR.
- Barnett, V., & Lewis, T. (1994). Outliers in Statistical Data. Wiley.


## 3. Step-by-Step Walkthrough
1. Load `telemetry_data.csv` into analysis script.
2. Compute mean $\mu$ and standard deviation $\sigma$ of sensor readings.
3. Filter data points where $Z = |x - \mu| / \sigma > 5.0$ to extract the hidden flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{zscore_statistical_anomaly_sensor_outlier_34aa}
```


## 5. Defense Engineering & Remediation
Sanitize and cryptographically sign telemetry sensor feeds to prevent unauthorized record injection.
