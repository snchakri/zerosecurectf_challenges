# Staged Hint Ladder: Invisible Unicode Steganography

### Hint Level 1
Zero-width characters (e.g. U+200B Zero-Width Space, U+200C Zero-Width Non-Joiner) do not render visibly in standard text editors.

### Hint Level 2
Parse the raw Unicode codepoints in Python: `ord(char)` or check for characters outside ASCII.

### Hint Level 3
Demodulate the sequence of ZWSP/ZWNJ characters into 8-bit binary bytes.

---
*Note: Crux Floor invariant: The core systems / analytical insight is never handed out completely; each hint restores a reasoning handle.*
