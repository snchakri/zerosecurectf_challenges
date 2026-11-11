# SCADA ICS Telemetry Extraction — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: SCADA ICS Telemetry Extraction (Modbus/TCP Holding Registers)


## 1. Vulnerability Analysis & Theoretical Foundations
Modbus/TCP lacks native encryption and authentication. Adversaries can inject unauthorized holding register write commands (Function Code 16) to manipulate industrial PLC logic or exfiltrate data.


## 2. Citations & Academic References
- Modbus Organization (2006). Modbus Application Protocol Specification V1.1b.
- Knapp, E. D., & Langill, J. T. (2014). Industrial Network Security. Syngress.


## 3. Step-by-Step Walkthrough
1. Inspect Modbus/TCP session dump in `scada_modbus_traffic.json`.
2. Extract 16-bit register hex values for Function Code 0x10.
3. Unpack big-endian 16-bit integers into ASCII characters to reconstruct the injected payload.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{modbus_scada_holding_registers_51aa}
```


## 5. Defense Engineering & Remediation
Deploy Modbus Security protocol extensions (TLS encapsulation) or industrial firewalls enforcing deep packet inspection (DPI) on Function Code 16.
