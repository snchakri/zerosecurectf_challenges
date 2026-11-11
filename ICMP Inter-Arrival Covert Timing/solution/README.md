# ICMP Inter-Arrival Covert Timing — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: ICMP Inter-Arrival Covert Timing (Network Telemetry Demodulation)


## 1. Vulnerability Analysis & Theoretical Foundations
Covert timing channels transmit unauthorized data across network boundaries by modulating the inter-packet arrival time intervals ($\Delta T$) of standard ICMP Echo packets, bypassing traditional deep packet inspection of payloads.


## 2. Citations & Academic References
- Cabuk, S., et al. (2004). IP covert timing channels: design and detection. ACM CCS 2004.
- Zander, S., et al. (2007). A survey of covert channels and countermeasure techniques. IEEE Communications Surveys & Tutorials.


## 3. Step-by-Step Walkthrough
1. Load packet arrival timestamps from `icmp_timing_trace.json`.
2. Calculate $\Delta T$ between consecutive packets.
3. Apply thresholding: $\Delta T \approx 100$ms $\to$ bit 0, $\Delta T \approx 500$ms $\to$ bit 1.
4. Convert the binary bitstream into 8-bit ASCII characters to extract the flag.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{icmp_covert_timing_channel_delta_10f0}
```


## 5. Defense Engineering & Remediation
Implement network traffic shaping and packet jitter normalization to eliminate timing variances in network streams.
