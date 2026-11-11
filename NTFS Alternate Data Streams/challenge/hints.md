# Staged Hint Ladder: NTFS Alternate Data Streams

### Hint Level 1
NTFS supports multiple data streams attached to a single file dentry (filename:streamname).

### Hint Level 2
Malware often hides secondary payloads in Alternate Data Streams to bypass naive file checks.

### Hint Level 3
Parse the $DATA attributes in the MFT record to isolate the hidden stream content.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
