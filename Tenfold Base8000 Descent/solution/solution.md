# Solution - Tenfold Base8000 Descent

## Approach
1. Implement the provided custom Base8000 decoder logic.
2. Read `challenge.txt` as UTF-8 text.
3. Decode exactly ten times in sequence.
4. The tenth decode returns the flag.

## Why Ten Rounds Matter
Each decode reveals another Base8000-encoded string, not plaintext.
The message chain is intentionally layered ten times.
Stopping before round ten yields intermediate encoded text only.

## Reference Result
After the tenth decode, the exact output is:

`ZeroSecure_CTF{caught_it_ten}`

## Validation
Use `validator.py` to verify the recovered flag string exactly.
