# Staged Hint Ladder: Side-Channel Padding Cryptanalysis

### Hint Level 1
CBC mode decryption XORs the decrypted block with the previous ciphertext block (or IV).

### Hint Level 2
By altering bytes of the previous block, you can force the decrypted block to end in 0x01, 0x02 0x02, etc.

### Hint Level 3
Work backwards from byte 15 to byte 0 for each ciphertext block.

---
*Note: Crux Floor invariant: The core cryptographic insight is never handed out completely; each hint restores a reasoning handle.*
