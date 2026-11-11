"""contract.py (PUBLIC) - Doom's token vault. Submit a transaction json:
  {"sender": "...", "recipients": ["...","..."], "value": <int>}
Usage (server-side):  python contract.py tx.json <flag_file>"""
import json, sys
MASK = (1 << 256) - 1
balances = {"vault": 1000000, "atkA": 1, "atkB": 0}
TOTAL_SUPPLY = 1000001
ATTACKER = ("atkA", "atkB")

def batchTransfer(sender, recipients, value):
    amount = (value * len(recipients)) & MASK          # <-- no overflow guard
    assert balances.get(sender, 0) >= amount, "insufficient balance"
    for r in recipients:
        balances[r] = (balances.get(r, 0) + value) & MASK
    balances[sender] = (balances.get(sender, 0) - amount) & MASK

tx = json.load(open(sys.argv[1]))
batchTransfer(tx["sender"], tx["recipients"], int(tx["value"]))
if any(balances.get(a, 0) > TOTAL_SUPPLY for a in ATTACKER):
    sys.stdout.buffer.write(b"MINTED " + open(sys.argv[2], "rb").read())
else:
    print("balances within supply; nothing minted")
