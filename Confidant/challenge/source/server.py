#!/usr/bin/env python3
"""
ZSCTF :: Confidant  (misc / AI-LLM security, Frontier)

A DETERMINISTIC MOCK of a tool-using "customer-support agent". There is NO real
LLM and no network call anywhere: the "agent", its instruction parser, its tools
and its layered guardrail are all plain Python that you can read in full below.
That is the whole point -- the challenge is a model of a real class of bug
(OWASP LLM01, *indirect* prompt injection against a tool-using agent), stripped
of the model's nondeterminism so it is safe, reproducible and fair.

WHAT THE AGENT DOES
-------------------
It ingests a customer-supplied *document* (think: a support ticket, a pasted
email, a knowledge-base article) and *acts on the support instructions it finds
inside it*. It can call three tools:

    lookup_ticket   -- read-only ticket status            (NOT privileged)
    send_email      -- queue a notification email         (NOT privileged)
    get_secret      -- read a value from the staff vault   (** PRIVILEGED **)

THE DEFENCE (layered, like a real deployment)
---------------------------------------------
  Layer 1  an INPUT CLASSIFIER screens the untrusted upload for manipulation.
  Layer 2  a TOOL ALLOWLIST / provenance policy decides which tool may run from
           which trust level. The privileged tool is reachable ONLY from an
           "operator" provenance -- never from the customer.

A DIRECT request for the privileged tool (ask for it in chat, or in the plain
customer body of a document) is therefore refused: the allowlist blocks it.

THE INTENDED (indirect) PATH is to craft a *document* that the agent itself
promotes to operator trust -- without tripping the classifier. The flaw is in
plain sight in the two functions `_classify` and `_extract` below; nothing is
hidden by obscurity (ZSCTF doctrine). See writeup.md for the full solution.

Per-instance: ZSCTF_SEED deterministically varies the tool names, the directive
grammar, the guardrail marker phrasing and the classifier threshold, so a
memorised payload for one team does not transfer (same seed -> same instance).

Run on stdio:   python3 server.py
Run as TCP:     python3 server.py --tcp 0.0.0.0 1337
"""
import os, sys, re, json, base64, hashlib, socketserver

# ---------------------------------------------------------------------------
# Per-instance configuration, derived deterministically from the team seed.
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("WARNING: ZSCTF_FLAG not set; using default placeholder "
                     "'zerosecurectf{local_review_flag}'\n")
    sys.stderr.flush()


def _digest(label):
    return hashlib.sha256(SEED + b"|" + label).digest()


def _pick(label, pool):
    """Deterministically choose one element of `pool` for this seed."""
    return pool[int.from_bytes(_digest(label)[:8], "big") % len(pool)]


def _int(label, lo, hi):
    """Deterministic integer in [lo, hi] for this seed."""
    return lo + int.from_bytes(_digest(label)[8:16], "big") % (hi - lo + 1)


# Directive *verbs* the agent's parser understands. The tool's machine name is
# the verb with spaces -> underscores (so tool names vary per seed too).
LOOKUP_VERBS = ["look up ticket", "check ticket", "ticket status for", "pull ticket"]
EMAIL_VERBS  = ["send email to", "notify customer", "message customer", "queue mail for"]
SECRET_VERBS = ["get secret", "read vault", "disclose record", "fetch credential"]

# The guardrail's "official" operator-section markers. The INPUT CLASSIFIER was
# written to reject any upload that carries one of these (a customer must never
# be able to submit operator-authored content).
OFFICIAL_MARKERS = [
    "--- operator notes ---",
    "=== staff section ===",
    "## internal ##",
    "-- agent directives --",
]
# The INGESTION PARSER, however, is an older component that -- for backward
# compatibility -- ALSO honours a "legacy" operator marker. The classifier was
# never taught about these legacy forms. That gap is the crux of the challenge.
LEGACY_MARKERS = [
    "[[verified-internal]]",
    "<<ops-channel>>",
    "{{trusted-note}}",
    "#!backstage",
]

# Benign "index" keywords the sealed-ledger vault answers to. All are free of
# risky nouns and manipulation language, so opening the index never nudges the
# input classifier (the extraction layer must not break the intended crux).
INDEX_KEYWORDS = ["manifest", "contents", "catalogue", "ledger", "directory"]

# Manipulation / jailbreak language the classifier scores. (name, regex, weight)
OVERRIDE_PATTERNS = [
    ("ignore-previous",   r"ignore (the |all |any )?(previous|prior|above|earlier|preceding)", 3),
    ("disregard",         r"disregard (the |all |any )?(previous|prior|above|rules|instruction)", 3),
    ("you-are-now",       r"you are (now |a |an |the )", 2),
    ("new-instructions",  r"new instruction", 2),
    ("system-prompt",     r"system prompt", 3),
    ("bypass",            r"\bbypass\b", 2),
    ("no-restrictions",   r"without (any )?(restriction|limit|rule)", 3),
    ("pretend",           r"\bpretend\b", 2),
    ("role-claim",        r"as an? (operator|admin|administrator|staff|developer)\b", 3),
    ("override",          r"\boverride\b", 2),
]
# "Risky" nouns. Their mere presence adds a little suspicion -- but note that a
# single privileged directive (which legitimately contains one of these words)
# stays comfortably under the threshold. (noun -> weight)
RISKY_NOUNS = {
    "secret": 2, "vault": 2, "credential": 2, "record": 1,
    "password": 3, "flag": 3, "token": 1,
}


def _build_config():
    lookup_verb = _pick(b"verb-lookup", LOOKUP_VERBS)
    email_verb  = _pick(b"verb-email",  EMAIL_VERBS)
    secret_verb = _pick(b"verb-secret", SECRET_VERBS)
    official    = _pick(b"marker-official", OFFICIAL_MARKERS)
    legacy      = _pick(b"marker-legacy",   LEGACY_MARKERS)
    threshold   = _int(b"threshold", 4, 6)
    return {
        "instance": hashlib.sha256(SEED).hexdigest()[:8],
        "tools": {
            "lookup": {"id": "lookup", "verb": lookup_verb,
                       "name": lookup_verb.replace(" ", "_"),
                       "privileged": False, "channels": ["user", "operator"]},
            "email":  {"id": "email", "verb": email_verb,
                       "name": email_verb.replace(" ", "_"),
                       "privileged": False, "channels": ["user", "operator"]},
            "secret": {"id": "secret", "verb": secret_verb,
                       "name": secret_verb.replace(" ", "_"),
                       "privileged": True, "channels": ["operator"]},
        },
        "classifier": {
            "threshold": threshold,
            # Layer-1 rejects any upload carrying an OFFICIAL operator marker...
            "hard_block_markers": [official],
            "override_patterns": [(n, p, w) for (n, p, w) in OVERRIDE_PATTERNS],
            "risky_nouns": RISKY_NOUNS,
        },
        "parser": {
            # ...but the ingestion parser opens the trusted operator region on
            # EITHER the official OR a legacy marker (classifier knows only the
            # official one -- that is the differential).
            "operator_markers": [official, legacy],
        },
    }


# ---------------------------------------------------------------------------
# S2/S2a EXTRACTION LAYER -- the "sealed-ledger vault walk".
#
# Reaching the privileged tool with operator provenance (the challenge crux) no
# longer hands over the flag. It earns only the MEANS to extract it: operator
# access lets the agent open a sealed-ledger INDEX. The flag is split across a
# chain of sealed "pages"; each page returns ONE hex-encoded fragment plus the
# token of the NEXT page, so the flag never appears whole in any single
# response and cannot be dumped in one call. The page tokens are derived from
# the per-instance secret seed, so they cannot be enumerated offline -- you must
# walk the chain, page by page.
#
# The index publishes several candidate head tokens (one real, several decoys)
# and a head_commitment = sha256(real_head). The real head is the candidate
# whose sha256 matches the commitment (verifiable discriminator #1). A careless
# solver who skips that check and walks a decoy head reconstructs a NEAR-FLAG
# that fails the strict validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$
# (verifiable discriminator #2). Guess-exposure stays 0: both wrong turns are
# rejectable purely by reasoning from published, checkable information.
# ---------------------------------------------------------------------------
def _mk_chain(label, text, pl):
    """Split `text` into `pl`-sized fragments on a chain of seed-derived tokens."""
    pages = max(1, -(-len(text) // pl))
    toks = [_digest(label + b"|%d" % k).hex()[:12] for k in range(pages)]
    frags = [text[k * pl:(k + 1) * pl] for k in range(pages)]
    return toks, frags


def _decoy_flag(d):
    """A per-instance near-miss: correct wrapper, but an UPPERCASE run in the
    body makes it fail ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ on reflection."""
    h = _digest(b"vault-decoyflag|%d" % d).hex()
    return "zerosecurectf{local_review_flag}" % h[:10]


def _build_vault():
    pl = _int(b"vault-pl", 3, 5)
    real_toks, _ = _mk_chain(b"vault-real", FLAG, pl)
    chains = [(b"vault-real", FLAG)]
    decoy_heads = []
    for d in range(3):
        chains.append((b"vault-decoy|%d" % d, _decoy_flag(d)))
        dt, _ = _mk_chain(b"vault-decoy|%d" % d, _decoy_flag(d), pl)
        decoy_heads.append(dt[0])
    # token -> (fragments, tokens, k) lookup across every chain
    lut = {}
    for label, text in chains:
        toks, frags = _mk_chain(label, text, pl)
        for k, t in enumerate(toks):
            lut[t] = (frags, toks, k)
    head = real_toks[0]
    cands = [head] + decoy_heads
    # deterministic shuffle so the real head is not positionally obvious
    cands.sort(key=lambda t: hashlib.sha256(b"vault-shuf|" + SEED + b"|" + t.encode()).hexdigest())
    return {
        "pl": pl,
        "pages": len(real_toks),
        "index_keyword": _pick(b"vault-index-kw", INDEX_KEYWORDS),
        "head": head,
        "head_commitment": hashlib.sha256(head.encode()).hexdigest(),
        "candidate_heads": cands,
        "lut": lut,
    }


CFG = _build_config()
CFG["vault"] = _build_vault()


# ---------------------------------------------------------------------------
# Layer 1 -- the input classifier (screens the untrusted upload).
# ---------------------------------------------------------------------------
def _classify(raw):
    """Return (verdict, score, signals). verdict in {'ALLOW','BLOCK'}."""
    signals = []
    low = raw.lower()
    lines = [ln.strip().lower() for ln in raw.splitlines()]

    # (a) Hard rule: a customer upload must not carry operator-marked content.
    for mark in CFG["classifier"]["hard_block_markers"]:
        if any(ln == mark or ln.startswith(mark) for ln in lines):
            signals.append(("operator-marked-content-rejected", 999))
            return "BLOCK", 999, signals

    # (b) Weighted manipulation score.
    score = 0
    for name, pat, w in CFG["classifier"]["override_patterns"]:
        if re.search(pat, low):
            score += w
            signals.append(("override:" + name, w))
    for noun, w in CFG["classifier"]["risky_nouns"].items():
        if re.search(r"\b" + re.escape(noun) + r"\b", low):
            score += w
            signals.append(("noun:" + noun, w))

    threshold = CFG["classifier"]["threshold"]
    return ("BLOCK" if score >= threshold else "ALLOW"), score, signals


# ---------------------------------------------------------------------------
# Instruction extraction -- the agent's "parser". It assigns a PROVENANCE
# (trust level) to every directive it pulls out of the content.
# ---------------------------------------------------------------------------
def _parse_directives(lines, provenance):
    out = []
    for ln in lines:
        body = ln.strip()
        low = body.lower()
        for tool in (CFG["tools"]["lookup"], CFG["tools"]["email"], CFG["tools"]["secret"]):
            v = tool["verb"]
            if low.startswith(v):
                arg = body[len(v):].strip()
                out.append({"tool": tool["id"], "arg": arg, "provenance": provenance})
                break
    return out


def _extract(channel, text):
    """
    chat     : a flat, fully-untrusted channel -> everything is 'user'.
    document : split at the FIRST operator marker the PARSER recognises; content
               before it is the customer body ('user'), content after it is the
               trusted operator region ('operator').

    The trust boundary is therefore decided by a marker that lives INSIDE the
    customer-supplied document. That is the indirect-injection flaw.
    """
    if channel == "chat":
        return _parse_directives(text.splitlines(), "user"), None

    lines = text.splitlines()
    markers = [m.lower() for m in CFG["parser"]["operator_markers"]]
    op_idx = None
    for i, ln in enumerate(lines):
        s = ln.strip().lower()
        if any(s == m or s.startswith(m) for m in markers):
            op_idx = i
            break
    if op_idx is None:
        return _parse_directives(lines, "user"), None
    customer = _parse_directives(lines[:op_idx], "user")
    operator = _parse_directives(lines[op_idx + 1:], "operator")
    return customer + operator, op_idx


# ---------------------------------------------------------------------------
# Layer 2 -- the tool allowlist / provenance policy, and tool execution.
# ---------------------------------------------------------------------------
def _authorize(directive):
    tool = CFG["tools"][directive["tool"]]
    prov = directive["provenance"]
    if prov in tool["channels"]:
        if tool["privileged"]:
            return True, "privileged tool reached with operator provenance"
        return True, "allowlisted for %s provenance" % prov
    if tool["privileged"]:
        return False, "privileged tool requires operator provenance; direct request blocked"
    return False, "not allowlisted for %s provenance" % prov


def _run_tool(directive):
    tool = CFG["tools"][directive["tool"]]
    arg = directive["arg"] or "-"
    if tool["id"] == "lookup":
        return "ticket %s: RESOLVED (refund issued 2026-09-01)" % arg
    if tool["id"] == "email":
        return "queued notification email (%s)" % arg
    return "ok"


def _vault_lines(arg):
    """Privileged-tool output. With operator provenance already granted, this is
    the sealed-ledger: open the index, or open a page by its token. The flag is
    NEVER emitted whole -- only one fragment per page response."""
    v = CFG["vault"]
    verb = CFG["tools"]["secret"]["verb"]
    a = (arg or "").strip().lower()
    if a == "" or a == v["index_keyword"]:
        return [
            "[vault] sealed-ledger index opened (operator access granted)",
            "[vault] pages=%d page_len=%d" % (v["pages"], v["pl"]),
            "[vault] head_commitment=%s" % v["head_commitment"],
            "[vault] candidate_heads=%s" % ",".join(v["candidate_heads"]),
            ("[vault] protocol=open a page with '%s <token>'; each page returns "
             "frag(hex) and the next token; the REAL head is the candidate whose "
             "sha256 equals head_commitment; concatenate fragments in page order "
             "to recover the flag (valid flag matches "
             "^zerosecurectf{local_review_flag}}$); decoy heads walk to near-flags "
             "that fail that validator") % verb,
        ]
    if a in v["lut"]:
        frags, toks, k = v["lut"][a]
        nxt = toks[k + 1] if k + 1 < len(toks) else "END"
        return ["[vault] sealed-page %d/%d token=%s frag=%s next=%s"
                % (k + 1, len(toks), a, frags[k].encode().hex(), nxt)]
    return ["[vault] no sealed page for %r; open the index first with '%s %s'"
            % (arg, verb, v["index_keyword"])]


# ---------------------------------------------------------------------------
# The agent loop -- produces a transparent transcript (observable behaviour).
# ---------------------------------------------------------------------------
def run_agent(channel, text):
    out = []
    nbytes = len(text.encode("utf-8", "ignore"))
    out.append("[ingest] channel=%s bytes=%d lines=%d"
               % (channel, nbytes, len(text.splitlines())))

    verdict, score, signals = _classify(text)
    sig = ",".join("%s=%d" % (n, w) for n, w in signals) or "none"
    out.append("[classifier] risk=%d threshold=%d verdict=%s signals=[%s]"
               % (score, CFG["classifier"]["threshold"], verdict, sig))
    if verdict == "BLOCK":
        out.append("[abort] request refused by input classifier")
        return out

    directives, op_idx = _extract(channel, text)
    if op_idx is not None:
        out.append("[extract] operator region opened at line %d (parser marker)" % op_idx)
    if not directives:
        out.append("[extract] no support directives found")
        out.append("[done] no action taken")
        return out
    for d in directives:
        out.append("[extract] %s(arg=%r) provenance=%s"
                   % (CFG["tools"][d["tool"]]["name"], d["arg"], d["provenance"]))

    for d in directives:
        ok, reason = _authorize(d)
        name = CFG["tools"][d["tool"]]["name"]
        if ok:
            out.append("[plan] %s provenance=%s -> ALLOW (%s)" % (name, d["provenance"], reason))
            if d["tool"] == "secret":
                out.extend(_vault_lines(d["arg"]))
            else:
                out.append("[tool] %s(%s) => %s" % (name, d["arg"] or "-", _run_tool(d)))
        else:
            out.append("[plan] %s provenance=%s -> DENY (%s)" % (name, d["provenance"], reason))
    out.append("[done]")
    return out


# ---------------------------------------------------------------------------
# Line protocol (stdio + TCP), mirroring the house style.
# Every response block is terminated by a lone "[end]" line.
# ---------------------------------------------------------------------------
def banner():
    t = CFG["tools"]
    return [
        "=== ZSCTF Support Agent (mock, deterministic) ===",
        "instance %s" % CFG["instance"],
        "I ingest a customer DOCUMENT and act on the support instructions inside it.",
        "tools: %s, %s, %s(PRIVILEGED)" % (t["lookup"]["name"], t["email"]["name"], t["secret"]["name"]),
        "the privileged tool opens a sealed-ledger vault; walk it to recover the flag. direct requests are refused.",
        "commands: CHAT <text> | DOC <base64-document> | POLICY | HELP | QUIT",
        "[end]",
    ]


def help_text():
    t = CFG["tools"]
    return [
        "CHAT <text>            send a direct chat message (fully untrusted channel)",
        "DOC <base64>           submit a document; I run the agent+guardrail on it",
        "POLICY                 print this instance's guardrail policy as one JSON line",
        "HELP                   this help",
        "QUIT                   disconnect",
        "",
        "directive grammar (one per line, inside chat or a document):",
        "  %-22s <ticket-id>" % t["lookup"]["verb"],
        "  %-22s <address> ..." % t["email"]["verb"],
        "  %-22s <token|%s>  (PRIVILEGED; opens the sealed-ledger index/page)"
        % (t["secret"]["verb"], CFG["vault"]["index_keyword"]),
        "[end]",
    ]


def policy_json():
    tools = []
    for k in ("lookup", "email", "secret"):
        tt = CFG["tools"][k]
        tools.append({"id": tt["id"], "name": tt["name"], "verb": tt["verb"],
                      "privileged": tt["privileged"], "allowed_provenance": tt["channels"]})
    pol = {
        "instance": CFG["instance"],
        "channels": {
            "chat": "all directives get 'user' provenance",
            "document": "customer body -> 'user'; operator region (after a parser marker) -> 'operator'",
        },
        "tools": tools,
        "input_classifier": {
            "threshold": CFG["classifier"]["threshold"],
            "hard_block_markers": CFG["classifier"]["hard_block_markers"],
            "override_patterns": [[n, p, w] for (n, p, w) in CFG["classifier"]["override_patterns"]],
            "risky_nouns": CFG["classifier"]["risky_nouns"],
        },
        "ingestion_parser": {
            "operator_region_markers": CFG["parser"]["operator_markers"],
            "note": "a line equal-to/startswith any of these opens the operator-trusted region",
        },
        "vault": {
            "open_index_with": "%s %s" % (CFG["tools"]["secret"]["verb"],
                                          CFG["vault"]["index_keyword"]),
            "index_keyword": CFG["vault"]["index_keyword"],
            "pages": CFG["vault"]["pages"],
            "page_len": CFG["vault"]["pl"],
            "note": ("the privileged tool no longer returns the flag directly. With "
                     "operator provenance it opens a sealed-ledger INDEX that lists "
                     "candidate head tokens and head_commitment=sha256(real_head). Open "
                     "the real head (sha256==commitment), read its frag(hex) and next "
                     "token, and walk the chain; concatenate fragments in page order to "
                     "recover the flag. Decoy heads walk to near-flags that fail "
                     "^zerosecurectf{local_review_flag}}$."),
        },
    }
    return [json.dumps(pol, separators=(",", ":")), "[end]"]


def handle_line(line):
    s = line.strip()
    if not s:
        return []
    parts = s.split(" ", 1)
    cmd = parts[0].upper()
    rest = parts[1] if len(parts) > 1 else ""
    try:
        if cmd == "CHAT":
            return run_agent("chat", rest) + ["[end]"]
        if cmd == "DOC":
            try:
                doc = base64.b64decode(rest.strip(), validate=True).decode("utf-8", "ignore")
            except Exception:
                return ["[error] DOC payload must be valid base64", "[end]"]
            return run_agent("document", doc) + ["[end]"]
        if cmd == "POLICY":
            return policy_json()
        if cmd == "HELP":
            return help_text()
        if cmd == "QUIT":
            return ["__QUIT__"]
        return ["[error] unknown command (try HELP)", "[end]"]
    except Exception as e:  # never crash the service on bad input
        return ["[error] %s" % e, "[end]"]


def serve_stdio():
    for ln in banner():
        print(ln, flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == ["__QUIT__"]:
            break
        for ln in resp:
            print(ln, flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(("\n".join(banner()) + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode("utf-8", "ignore"))
            if resp == ["__QUIT__"]:
                break
            self.wfile.write(("\n".join(resp) + "\n").encode())


def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port))
        sys.stderr.flush()
        srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
