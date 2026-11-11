"""
orchestrator.py - the only tool that renders containers.  (Part of the handout.)
Usage:  python orchestrator.py containers.json <cell_id> <cell_id> ...

It derives the key from the TEMPERATURES OF THE CELLS YOU SELECT, IN THE ORDER
YOU GIVE THEM, then peels each selected cell's payload. If every selected cell
peels to a valid HEAT fragment and the fragments form one complete flag, it
renders the flag. Otherwise the render stalls into a deadlock and leaks a decoy.
"""
import json, sys, hashlib
from Crypto.Cipher import AES

MAGIC = b"HEAT"


def nonce(cid):
    return hashlib.sha256(b"nonce|" + bytes([cid])).digest()[:8]


def render(containers_path, seq):
    H = json.loads(open(containers_path).read())
    K = H["fragments"]
    by_id = {c["id"]: c for c in H["containers"]}
    temps = [by_id[i]["temp"] for i in seq]                       # YOUR order, as given
    key = hashlib.sha256(b"rubix-heat|" + bytes(temps)).digest()[:16]
    # the heat sink keys off the exact temperature pattern you feed it: wrong set
    # OR wrong order (the pattern is not rising) -> wrong key -> deadlock.
    frags = {}
    ok = True
    for i in seq:
        ct = bytes.fromhex(by_id[i]["payload"])
        pt = AES.new(key, AES.MODE_CTR, nonce=nonce(i)).decrypt(ct)
        if pt[:4] != MAGIC:
            ok = False
            break
        frags[pt[4]] = pt[5:]
    if ok and len(seq) == K and set(frags) == set(range(K)):
        return "FLAG " + b"".join(frags[p] for p in range(K)).decode(errors="replace")
    leak = hashlib.sha256(b"leak|" + bytes(seq)).hexdigest()[:12]
    return "DEADLOCK (memory-leak decoy): zerosecurectf{" + leak + "}"


if __name__ == "__main__":
    print(render(sys.argv[1], [int(x) for x in sys.argv[2:]]))
