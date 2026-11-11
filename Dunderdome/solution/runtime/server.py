#!/usr/bin/env python3
"""
ZSCTF :: Dunderdome  (misc / pyjail, Hard)

    "Two underscores enter. None leave."

A Python expression sandbox. You send ONE expression; the jail parses it,
screens it against a restriction model, and evaluates it under a *restricted
builtins table*. The flag lives only in this process's environment variable
ZSCTF_FLAG (never on disk). Your job is to make the jail hand it to you anyway.

Players are given this exact source file. The restriction model is therefore
NOT hidden behind obscurity -- it is in plain sight below (see `screen()` and
the `HARD_BANNED` / `CORE_ALLOWED` / `POOL` tables). That is the point: the
route is reachable purely by reasoning about what the filter does and does not
cover. There is no guessing.

The restriction model, in one breath:
  * exactly one expression (Python `eval` mode: no statements/imports/assigns);
  * ASCII only, <= 4096 bytes;
  * the two-character sequence "__" may not appear anywhere, and no identifier
    may contain "__"  -> you cannot *type* a dunder;
  * a visible deny-list of identifiers (names/attributes/kwargs);
  * a small, per-instance allow-list of builtins -- everything else is gone.

Self-contained: pure-Python standard library only.
"""
import os
import sys
import ast
import random
import hashlib
import builtins
import socketserver

# ----------------------------------------------------------------------------
# Per-instance flag. It lives ONLY in the environment, never on disk and never
# in an image layer. We pin it into os.environ so the intended escape (which
# reads os.environ) always has something real to recover, even if an operator
# forgot the -e flag during a quick local run.
# ----------------------------------------------------------------------------
DEFAULT_FLAG = "zerosecurectf{br3ak_th3_d0me_w1th0ut_a_s1ngl3_dund3r}"
os.environ.setdefault("ZSCTF_FLAG", DEFAULT_FLAG)

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()

LIMIT = 4096  # max bytes of a single submitted expression

# ----------------------------------------------------------------------------
# THE RESTRICTION MODEL (this is the whole challenge -- read it)
# ----------------------------------------------------------------------------
# CORE_ALLOWED : builtins that ALWAYS exist and are NEVER banned. Kept tiny.
#                `getattr` + `chr` are the load-bearing primitives the intended
#                escape needs; the rest are for basic usability/exploration.
CORE_ALLOWED = frozenset({
    "getattr", "chr", "ord", "str", "len", "range", "tuple", "list", "bool",
})

# HARD_BANNED : identifiers rejected on EVERY instance. Two groups:
#   (a) builtins that would hand you code-exec / import / raw namespaces; and
#   (b) "leaky" frame/code attribute names (blocked in their literal `x.attr`
#       form -- see the honest note in writeup.md about getattr-constructed
#       strings). Names containing "__" are listed for documentation only; the
#       "__" rule already blocks them before the name check ever runs.
HARD_BANNED = frozenset({
    # (a) direct code execution / import / namespace access
    "eval", "exec", "compile", "open", "input", "breakpoint",
    "help", "exit", "quit", "license", "credits", "copyright",
    "globals", "locals", "vars", "dir", "memoryview",
    "__import__", "__builtins__",
    # (b) frame / code / traceback leak vectors (literal-attribute form)
    "f_globals", "f_locals", "f_back", "f_builtins", "f_code",
    "gi_frame", "gi_code", "cr_frame", "ag_frame", "tb_frame", "tb_next",
})

# POOL : safe builtins that MAY be banned, chosen per-instance from ZSCTF_SEED.
#        This is the Prison-Reform-style "tune the ban-list" knob: the exact
#        set of available tools differs per team, which closes off some
#        alternative routes without ever touching the intended path (the
#        intended path uses only CORE_ALLOWED names).
POOL = frozenset({
    "abs", "min", "max", "sum", "sorted", "map", "filter", "zip", "enumerate",
    "reversed", "any", "all", "hex", "oct", "bin", "int", "float", "complex",
    "bytes", "bytearray", "set", "frozenset", "dict", "hash", "id", "type",
    "object", "slice", "format", "repr", "round", "pow", "divmod", "ascii",
    "hasattr", "isinstance", "issubclass", "iter", "next", "callable",
})

# Invariants: the three tables must stay disjoint, or the "always available"
# guarantee for the intended path could silently break.
assert CORE_ALLOWED.isdisjoint(HARD_BANNED), "core overlaps hard-ban"
assert CORE_ALLOWED.isdisjoint(POOL), "core overlaps pool"
assert POOL.isdisjoint(HARD_BANNED), "pool overlaps hard-ban"


def _rng(seed_bytes):
    """Deterministic RNG seeded from the instance seed (same seed -> same jail)."""
    return random.Random(int.from_bytes(hashlib.sha256(seed_bytes).digest(), "big"))


def instance_config(seed_bytes):
    """Derive (banned_identifiers, available_builtin_names) for this instance.

    Roughly half of POOL is banned, chosen deterministically from the seed.
    CORE_ALLOWED is always available; HARD_BANNED is always banned.
    """
    rng = _rng(seed_bytes)
    pool = sorted(POOL)                      # stable population order
    banned_pool = frozenset(rng.sample(pool, len(pool) // 2))
    banned = HARD_BANNED | banned_pool
    available = CORE_ALLOWED | (POOL - banned_pool)
    return banned, available


BANNED, AVAILABLE = instance_config(SEED)

# Build the restricted builtins table actually handed to eval().
SAFE_BUILTINS = {n: getattr(builtins, n) for n in AVAILABLE if hasattr(builtins, n)}


# ----------------------------------------------------------------------------
# The screen: the only thing standing between the player and a normal eval().
# ----------------------------------------------------------------------------
def _bad_ident(name):
    if "__" in name:
        return "identifier %r contains '__'" % name
    if name in BANNED:
        return "identifier %r is banned" % name
    return None


def screen(src):
    """Return (ok, reason). ok=True means the source passed every rule."""
    if not src.strip():
        return False, "empty input"
    if len(src) > LIMIT:
        return False, "too long (> %d bytes)" % LIMIT
    try:
        src.encode("ascii")
    except UnicodeEncodeError:
        return False, "non-ASCII characters are banned"
    # Rule: you cannot TYPE a dunder (two adjacent underscores) anywhere.
    if "__" in src:
        return False, "the sequence '__' is banned"
    # Rule: exactly one expression -- eval mode forbids statements outright.
    try:
        tree = ast.parse(src, mode="eval")
    except SyntaxError as e:
        return False, "not a single expression (%s)" % e.msg
    # Rule: no banned / dunder identifier anywhere it can appear.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return False, "imports are banned"
        bad = None
        if isinstance(node, ast.Name):
            bad = _bad_ident(node.id)
        elif isinstance(node, ast.Attribute):
            bad = _bad_ident(node.attr)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            bad = _bad_ident(node.arg)
        elif isinstance(node, ast.arg):
            bad = _bad_ident(node.arg)
        if bad:
            return False, bad
    return True, ""


def run_expr(src):
    """Screen, then evaluate. Returns a single protocol line to send back."""
    ok, reason = screen(src)
    if not ok:
        return "REJECTED " + reason
    try:
        code = compile(src, "<dunderdome>", "eval")
    except SyntaxError as e:
        return "REJECTED not a single expression (%s)" % e.msg
    try:
        result = eval(code, {"__builtins__": SAFE_BUILTINS}, {})
    except Exception as e:                      # player code may raise anything
        return "ERROR %s: %s" % (type(e).__name__, e)
    text = result if isinstance(result, str) else repr(result)
    # Keep the protocol one-line-per-response so scripted clients can parse it.
    return "RESULT " + text.replace("\n", "\\n")


# ----------------------------------------------------------------------------
# Line protocol (stdio + TCP), identical shape to the rest of the ZSCTF corpus.
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF :: Dunderdome ===")
    out.append("Two underscores enter. None leave.")
    out.append("")
    out.append("Send ONE Python expression. It is screened, then eval'd under a")
    out.append("restricted builtins table. The flag is in this process's")
    out.append("environment (ZSCTF_FLAG). Reach it. Rules (also in server.py):")
    out.append("  1. ASCII only; one line; <= %d bytes; a single expression" % LIMIT)
    out.append("     (eval mode: no statements, imports, assignments or ';').")
    out.append("  2. '__' may not appear anywhere; no identifier may contain '__'.")
    out.append("  3. banned identifiers: " + " ".join(sorted(BANNED)))
    out.append("  4. builtins available: " + " ".join(sorted(AVAILABLE)))
    out.append("commands: <expression> | QUIT")
    return "\n".join(out)


def handle_line(line):
    s = line.strip()
    if not s:
        return ""
    if s.upper() == "QUIT":
        return "__QUIT__"
    return run_expr(line.rstrip("\n"))


def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode(errors="ignore"))
            if resp == "__QUIT__":
                break
            if resp:
                self.wfile.write((resp + "\n").encode())


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
