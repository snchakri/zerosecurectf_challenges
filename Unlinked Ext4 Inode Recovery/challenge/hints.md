# Staged Hint Ladder: Unlinked Ext4 Inode Recovery

### Hint Level 1
When a file is unlinked on ext4, its dentry is wiped, but the inode and data extent blocks remain intact until overwritten.

### Hint Level 2
Check for ext4 extent headers (magic 0xF30A) or scan sector blocks for unallocated resident text.

### Hint Level 3
Locate the deleted configuration block containing the operational flag.

---
*Note: Crux Floor invariant: The core forensic recovery technique is never handed out completely; each hint restores a reasoning handle.*
