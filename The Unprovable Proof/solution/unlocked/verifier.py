"""verifier.py (PUBLIC) - the Keystone's proof check. Broken: c binds only the
message, not the commitment t, so t can be chosen after c. Usage (server-side):
  python verifier.py params.json proof.json <flag_file>"""
import json, sys, hashlib
P = json.load(open(sys.argv[1])); proof = json.load(open(sys.argv[2]))
c = int.from_bytes(hashlib.sha256(P["message"].encode()).digest(), "big") % P["q"]
t, s = int(proof["t"]), int(proof["s"])
if pow(P["g"], s, P["p"]) == (t * pow(P["y"], c, P["p"])) % P["p"]:
    sys.stdout.buffer.write(b"VALID " + open(sys.argv[3], "rb").read())
else:
    print("INVALID - the throne is not fooled")
