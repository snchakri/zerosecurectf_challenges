# The Overflow Vault — solution

Run from the title directory:

```bash
python -m pip install -r solution/requirements.txt
python solution/solve.py
```

The narrative gate answer is **`godhood`**. In `challenge/`, run `python open.py gate.bin "godhood"` to render the puzzle. The reference solver can also use the identical rendered handout retained in `solution/unlocked/`. The launcher fixes the original station identifier so that renaming the outer folder does not change the gate key.

1. Open the narrative gate with **godhood**.
2. The transfer checks `value*recipient_count` modulo `2^256`. Choose value `2^255` and two distinct attacker recipients.
3. The checked total wraps to zero, so the balance check passes, while each attacker receives `2^255`, exceeding the total supply.
4. Submit the generated transaction to the public contract model. The local replay releases the archived answer only after the contract accepts the exploit.

The accepted event answer is recorded in `accepted_flags.txt`. The solver derives its result from the challenge data.
