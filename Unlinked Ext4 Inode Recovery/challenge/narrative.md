# Challenge: Unlinked Ext4 Inode Recovery (forensics_02_ext4_deleted_inode_carving)

**Category:** Forensics  
**Difficulty:** Medium  
**Format:** `zerosecurectf{...}`  
**North Star:** Authentic Tradecraft & Realistic Forensic Artifacts  

---

## Scenario & Objective
An adversary executed `rm -rf /opt/confidential/` on an ext4 root partition before terminating the VM. Perform file system carving on the raw partition dump to reconstruct the unlinked file contents.

## Provided Files
- `fs_chunk.img`
- `solve.py`: Automated solver and verification reference.

## Compliance
- Universal Format asserted: `zerosecurectf{...}`
- Zero unreasoned guessiness.
