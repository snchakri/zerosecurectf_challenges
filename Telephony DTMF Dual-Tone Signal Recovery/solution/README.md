# Telephony DTMF Dual-Tone Signal Recovery — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Telephony DTMF Dual-Tone Signal Recovery (Frequency Demodulation)


## 1. Vulnerability Analysis & Theoretical Foundations
Telephone keypad dial tones combine two audible frequencies. Intercepted audio streams can be decoded into dial digits using the Goertzel algorithm.


## 2. Citations & Academic References
- Goertzel, G. (1958). An algorithm for the evaluation of finite trigonometric series.
- ITU-T Recommendation Q.23 (1988). Technical features of push-button telephone sets.


## 3. Step-by-Step Walkthrough
1. Analyze frequency pairs in `dtmf_telephony.json`.
2. Map frequency combinations (e.g. 697 Hz + 1209 Hz $\to$ '1').
3. Reconstruct the decoded authorization token.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{dtmf_dual_tone_frequencies_telephony_18bb}
```


## 5. Defense Engineering & Remediation
Never transmit sensitive authentication codes or PINs across unencrypted analog audio channels.
