# Staged Hint Ladder: SCADA ICS Telemetry Extraction

### Hint Level 1
Modbus Function Code 16 (0x10) writes blocks of 16-bit registers.

### Hint Level 2
Each 16-bit register stores two ASCII characters in big-endian byte order.

### Hint Level 3
Reconstruct the byte stream from the register values.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
