# Unlinked Ext4 Inode Recovery — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Unlinked Ext4 Inode Recovery (Filesystem Extent Tree Carving)


## 1. Vulnerability Analysis & Theoretical Foundations
On ext4 filesystems, unlinking a file (`rm`) clears directory entries (dentry), but the inode extent tree and data blocks remain on disk until allocated and overwritten by new writes.


## 2. Citations & Academic References
- Carrier, B. (2005). File System Forensic Analysis. Addison-Wesley.
- Mathur, A., et al. (2007). The new ext4 filesystem: current status and future plans. OLS 2007.


## 3. Step-by-Step Walkthrough
1. Inspect `fs_chunk.img` using binary stream analysis.
2. Search for ext4 superblock magic 0xEF53 and extent header magic 0xF30A.
3. Carve unallocated resident data blocks containing the unlinked file string.


## 4. Exploit Script & Verification
Execute the automated reference solver:
```bash
python solve.py
```
Output:
```text
[+] Successfully recovered flag: zerosecure{ext4_extent_tree_carved_inode_8871}
```


## 5. Defense Engineering & Remediation
Utilize secure shredding utilities (`srm`, `shred`) or enable filesystem encryption (fscrypt) to wipe deleted plaintext blocks.
