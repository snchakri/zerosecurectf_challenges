#!/usr/bin/env python3
"""
Latverian Computational Sandbox -- restricted expression evaluator.

Submit ONE Python expression on stdin. It is accepted only if it passes BOTH:
  * a source blacklist: the characters  _ . ' " [ ] { }  a backslash and a
    semicolon may not appear, and none of the words
    import / eval / exec / compile / open / system / global;
  * an AST whitelist: only expressions built from calls, names, integer
    literals and the arithmetic operators (^ + - * %) plus generator
    expressions are allowed. Attribute access, subscripting and string/bytes
    literals are rejected.

The sandbox exposes a few harmless names and `data`, the citadel's sealed
record. Escaping the restrictions reveals what `data` really holds.
"""
import ast
import sys

# --- the sealed record: the flag, masked byte-by-byte with a keystream -------
data = b'\xdd\x9f?\xcf\x80#\xfa\x99M\xf7\x9eH\xf2\xb4P\xed\xbbu\x0e\xa5A\x15\xa5}\x1c\xb1p\x1b\xe4l\x14\xddk.\xc4n\x0c\xd2\x8b-\xe9\x977\xeb\x8aR\xce\xd3\x0f\xeb\xbeM'
S = 167
T = 83

BANNED_CHARS = set("_.'\"[]{}\\;`")
BANNED_WORDS = ("import", "eval", "exec", "compile", "open", "system",
                "global", "builtin")

ALLOWED_NODES = (
    ast.Expression, ast.Call, ast.Name, ast.Load, ast.Store,
    ast.Constant, ast.BinOp, ast.GeneratorExp, ast.comprehension,
    ast.Tuple,
    ast.BitXor, ast.Add, ast.Sub, ast.Mult, ast.Mod,
)

# names the restricted scope may use (no __builtins__)
SCOPE = {
    "getattr": getattr, "chr": chr, "ord": ord, "bytes": bytes,
    "bytearray": bytearray, "map": map, "tuple": tuple, "range": range,
    "len": len, "enumerate": enumerate, "sum": sum, "pow": pow,
    "data": data, "S": S, "T": T,
}


def source_ok(src):
    for ch in src:
        if ch in BANNED_CHARS:
            return False, "forbidden character %r" % ch
    low = src.lower()
    for w in BANNED_WORDS:
        if w in low:
            return False, "forbidden word %r" % w
    return True, ""


def ast_ok(tree):
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            return False, type(node).__name__
        if isinstance(node, ast.Constant) and type(node.value) is not int:
            return False, "non-int literal"
    return True, ""


def run(src):
    ok, why = source_ok(src)
    if not ok:
        return "REJECTED (source): " + why, False
    try:
        tree = ast.parse(src, "<jail>", "eval")
    except SyntaxError as e:
        return "REJECTED (syntax): %s" % e, False
    ok, why = ast_ok(tree)
    if not ok:
        return "REJECTED (ast): %s not allowed" % why, False
    try:
        g = dict(SCOPE)
        g["__builtins__"] = {}
        result = eval(compile(tree, "<jail>", "eval"), g)
    except Exception as e:
        return "ERROR: %r" % e, False
    return result, True


def main():
    src = sys.stdin.read().strip()
    result, ok = run(src)
    if not ok:
        sys.stdout.write(str(result) + "\n")
        return 1
    if isinstance(result, (bytes, bytearray)):
        sys.stdout.write(bytes(result).decode(errors="replace") + "\n")
    else:
        sys.stdout.write(str(result) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
