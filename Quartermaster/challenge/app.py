# ===========================================================================
# HANDOUT COPY -- for reading, not running. The custody-cipher helpers
# (_keystream, _permutation, _scramble, _xor_only) are REDACTED: their
# algorithms are named in the comments and docstrings below, but their code
# is withheld. Recover the flag by reconstructing the inverse from the
# described scheme and the two channels you read from your own live instance.
# ===========================================================================
#!/usr/bin/env python3
"""
ZSCTF :: Quartermaster  (web, Hard)

"Quartermaster" is a legacy internal *asset registry* console. Staff type an
asset tag (e.g. AST-1001) and the service looks it up in the company inventory
and returns the matching record. It is the sort of small internal tool that was
written years ago, never got a rewrite, and builds its one SQL query by *gluing
the user's input straight into a string* -- the textbook SQL-injection
(CWE-89) sink.

The public inventory lives in the `assets` table. Alongside it, on the same
database, sits a RESTRICTED custody registry that ops never exposed through any
endpoint -- decommissioned / sensitive records that regular staff are not meant
to read. One of those restricted records holds the flag. There is no "admin
login", no second endpoint, no header to forge: the *only* path from the public
inventory to the restricted registry is to make the one concatenated query do
something it was never meant to do.

This is a WHITE-BOX challenge: you are given this exact source file. The flaw is
therefore not hidden by obscurity -- it is in plain sight, in the one line that
builds `sql` by concatenation. The work is to turn that flaw into a read of the
restricted registry.

Why it is not a one-liner:
  * The flag is NOT in the table the query reads (`assets`). `' OR '1'='1' --`
    just dumps the public inventory -- no flag. You must pivot into the other
    table, which means a UNION with the *correct column count*.
  * The restricted table's NAME and the flag's COLUMN name are NOT fixed. They
    are derived per instance from ZSCTF_SEED (see `_derive` below) and are never
    printed anywhere. You cannot hardcode `SELECT flag FROM secrets`; you have
    to *enumerate the live schema* (`sqlite_master` / `pragma_table_info`) to
    discover them, then read the row. Same seed -> same schema; different team
    -> different schema, so a leaked answer does not transfer.

Zero third-party dependencies: standard-library `sqlite3` + `http.server` only.
`python app.py` serves on $PORT (default 8000).
"""
import os
import re
import sys
import json
import hashlib
import sqlite3
from urllib.parse import urlsplit, parse_qs

# ---------------------------------------------------------------------------
# Per-instance configuration (derived deterministically from the team seed).
#
# Nothing secret is baked into this file. The restricted table name, the flag
# column name and the flag itself are functions of ZSCTF_SEED / ZSCTF_FLAG,
# which are injected at run time and never shipped to players. Giving players
# this source therefore reveals the *mechanism* (a concatenated query, and the
# fact that the schema is seed-derived) but not the *answer* (the live names,
# which must be enumerated against their own running instance).
# ---------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{REPLACE_ME_AT_DEPLOY}")

# The PUBLISHED strict flag validator. A captured candidate is only the flag if
# it matches this. It is the reasoning handle that lets a careful solver REJECT
# every decoy in this challenge (guess-exposure 0): the real custody record
# satisfies it; every decoy violates it in an obvious-on-reflection way.
STRICT_FLAG = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


def _derive(label: bytes, nhex: int) -> str:
    """A stable hex slice of SHA-256(seed | label). Used for schema + key values."""
    return hashlib.sha256(SEED + b"|" + label).hexdigest()[:nhex]


# PUBLIC, non-secret: proves determinism to tooling without leaking anything.
FINGERPRINT = _derive(b"instance-fingerprint", 12)

# SEED-DERIVED SCHEMA VALUES (the per-instance "secret schema").
#   - the restricted custody registry's table name
#   - the two columns that together hold the ENCIPHERED flag (see below)
# All are valid SQLite identifiers (letter prefix + hex), and none is ever
# emitted by any endpoint. Players must enumerate them at run time.
REG_TABLE = "cust_" + _derive(b"registry-table", 8)
CT_COL    = "ct_"  + _derive(b"ciphertext-column", 8)   # channel 1: ciphertext
KEY_COL   = "km_"  + _derive(b"keymaterial-column", 8)   # channel 2: key material
REG_ROWTAG = "CR-" + _derive(b"registry-tag", 6).upper()  # the restricted record's own tag

# Defensive: these must be plain identifiers (they are derived from hex, so this
# always holds -- the assert documents the invariant and guards future edits).
_IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
assert _IDENT.match(REG_TABLE) and _IDENT.match(CT_COL) and _IDENT.match(KEY_COL), \
    "derived identifiers must be safe"

# ---------------------------------------------------------------------------
# THE CUSTODY CIPHER  (this is the flag-EXTRACTION layer -- white-box).
#
# The flag is NEVER stored in plaintext anywhere. The restricted custody record
# stores it ENCIPHERED and SPLIT across two columns, so that no single read --
# and no single UNION SELECT -- ever yields `zerosecurectf{...}`:
#
#   channel 1 (CT_COL):  ct[i] = flag[P[i]] XOR K[i]        (permute, then XOR)
#   channel 2 (KEY_COL): keymat = KMASK_HEX || PERM_HEX     (the key to invert)
#
# K (an XOR keystream) is expanded from KMASK_HEX; P (a permutation) is derived
# from PERM_HEX. Both seeds are themselves per-instance (SHA-256 of ZSCTF_SEED)
# and are printed NOWHERE. To recover the flag a solver must obtain BOTH the
# ciphertext (channel 1) AND the key material (channel 2) from their own live
# instance, then invert offline: un-XOR with K, then un-permute with P. Reading
# only one channel, or forgetting to un-permute, yields a rejectable near-flag.
#
# The mechanism is in plain sight (white-box); the per-instance KEY is not.
# ---------------------------------------------------------------------------
KMASK_HEX = _derive(b"custody-xor-mask", 32)      # 16-byte XOR keystream seed
PERM_HEX  = _derive(b"custody-permutation", 32)   # permutation seed
KEYMAT    = KMASK_HEX + PERM_HEX                   # 64 hex chars carried by KEY_COL


def _keystream(seed_hex: str, n: int) -> bytes:
    """Deterministic n-byte keystream = SHA-256 counter-mode over seed_hex."""
    raise NotImplementedError('redacted in this handout -- reconstruct from the scheme described above')


def _permutation(seed_hex: str, n: int) -> list:
    """Deterministic Fisher-Yates permutation of range(n), seeded by seed_hex."""
    raise NotImplementedError('redacted in this handout -- reconstruct from the scheme described above')


def _scramble(plain: str) -> str:
    """Permute-then-XOR the plaintext; return ciphertext as hex (channel 1)."""
    raise NotImplementedError('redacted in this handout -- reconstruct from the scheme described above')


def _xor_only(plain: str) -> str:
    """What 'un-XOR but FORGET to un-permute' recovers: the flag's characters in
    permuted order -- a format-invalid near-flag (the skip-the-unscramble trap)."""
    raise NotImplementedError('redacted in this handout -- reconstruct from the scheme described above')


PORT = int(os.environ.get("PORT", "8000"))

# ---------------------------------------------------------------------------
# The data.
#
# `assets` (the PUBLIC inventory) is identical on every instance -- it is not
# secret -- except for one seed-varied DECOY row (AST-0000) whose name is a
# flag-SHAPED near miss (uppercase body) that a lazy `OR 1=1` dump surfaces
# first and that fails the strict validator. The RESTRICTED registry holds the
# enciphered flag; its table/column names vary per instance (above).
# ---------------------------------------------------------------------------
ASSET_DECOY = "zerosecurectf{" + _derive(b"asset-decoy", 10).upper() + "}"  # uppercase -> invalid

PUBLIC_ASSETS = [
    # (tag, name, category, location)
    ("AST-0000", ASSET_DECOY, "archive", "Chennai-DC-B1"),   # R1 decoy: first thing a dump shows
    ("AST-1001", "ThinkPad X1 Carbon Gen 11", "laptop", "Chennai-HQ-3F"),
    ("AST-1002", "Dell UltraSharp U2720Q", "monitor", "Chennai-HQ-3F"),
    ("AST-1003", "Cisco Catalyst 9300", "network", "Chennai-DC-B1"),
    ("AST-1004", "APC Smart-UPS 1500VA", "power", "Chennai-DC-B1"),
    ("AST-1005", "Logitech MX Master 3S", "peripheral", "Remote-Store"),
    ("AST-1006", "Apple iPad Pro 11", "tablet", "Chennai-HQ-5F"),
]

# A decoy custody record: a flag-SHAPED near miss (it carries a hyphen, so it
# fails STRICT_FLAG). A solver who extracts and unscrambles the WRONG row gets
# this and can reject it by the published validator alone (guess-exposure 0).
DECOY_FLAG = "zerosecurectf{" + _derive(b"decoy-body", 16) + "-leak}"
DECOY_ROWTAG = "CR-ARCH-" + _derive(b"decoy-tag", 4).upper()

REAL_CT = "<computed on the live server at startup>"
DECOY_CT = "<computed on the live server at startup>"

# --- build-time invariant guards (documentation, not decoration) -------------
# The decoy and the skip-the-unscramble near-flag MUST be rejectable by the
# published validator; the enciphered channels MUST carry no plaintext flag.
assert not STRICT_FLAG.match(DECOY_FLAG), "decoy custody record must fail the strict validator"
assert not STRICT_FLAG.match(ASSET_DECOY), "asset decoy must fail the strict validator"
# (skip-un-permute near-flag guard runs on the server)
assert FLAG not in REAL_CT and FLAG not in KEYMAT, "no plaintext flag in either channel"

# Seed-chosen row order: the real custody record is NOT always row 1, so the
# solver must reason about WHICH row is real (discriminator: STRICT_FLAG).
_real_first = (int(_derive(b"row-order", 2), 16) % 2 == 0)
_r_real = (REG_ROWTAG, REAL_CT, KEYMAT, "RESTRICTED")
_r_decoy = (DECOY_ROWTAG, DECOY_CT, KEYMAT, "RESTRICTED")
_ordered = [_r_real, _r_decoy] if _real_first else [_r_decoy, _r_real]
# rows: (id, tag, CT_COL, KEY_COL, clearance)
REG_ROWS = [(i + 1,) + r for i, r in enumerate(_ordered)]


def build_db() -> sqlite3.Connection:
    """Build a fresh in-memory database for a single request.

    A brand-new connection per request means no shared mutable state and no
    thread-safety concerns under ThreadingHTTPServer, and nothing is ever
    written to disk (the deployment runs on a read-only filesystem). The data
    is tiny, so the rebuild cost is negligible.
    """
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE assets "
        "(id INTEGER PRIMARY KEY, tag TEXT, name TEXT, category TEXT, location TEXT)"
    )
    cur.executemany(
        "INSERT INTO assets (tag, name, category, location) VALUES (?, ?, ?, ?)",
        PUBLIC_ASSETS,
    )
    # Restricted registry: table + the two enciphered-channel columns are
    # seed-derived (safe identifiers). The flag is NOT stored in plaintext in
    # any column -- CT_COL holds the ciphertext, KEY_COL the key material.
    cur.execute(
        "CREATE TABLE %s "
        "(id INTEGER PRIMARY KEY, tag TEXT, %s TEXT, %s TEXT, clearance TEXT)"
        % (REG_TABLE, CT_COL, KEY_COL)
    )
    cur.executemany(
        "INSERT INTO %s (id, tag, %s, %s, clearance) VALUES (?, ?, ?, ?, ?)"
        % (REG_TABLE, CT_COL, KEY_COL),
        REG_ROWS,
    )
    con.commit()
    return con


# ---------------------------------------------------------------------------
# THE VULNERABLE LOOKUP  --  this one line is the whole challenge.
#
# The query is built by CONCATENATING the user's tag straight into the SQL text.
# The template reads only from `assets` and selects a fixed FOUR columns
# (tag, name, category, location). A normal tag works correctly. A crafted tag
# can close the string literal and append its own SQL -- including a UNION whose
# SELECT must have the SAME four-column arity to combine with the base query.
#
# The correct fix (shown for teaching; NOT used here) is parameterisation:
#     cur.execute("... WHERE tag = ?", (tag_value,))
# which would make the input pure data and close this challenge entirely.
# ---------------------------------------------------------------------------
BASE_SELECT = "SELECT tag, name, category, location FROM assets WHERE tag = '"


def do_lookup(tag_value: str) -> dict:
    con = build_db()
    try:
        sql = BASE_SELECT + tag_value + "'"          # <<< THE FLAW: string concatenation
        cur = con.cursor()
        # NOTE: execute() runs exactly ONE statement. Stacked queries such as
        # "'; DROP TABLE assets; --" raise ProgrammingError and change nothing,
        # so the injection is read-only. (executescript() is never used.)
        cur.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
        return {"ok": True, "columns": cols, "rows": rows, "count": len(rows)}
    except sqlite3.Error as e:
        # Legacy apps leak database errors. We keep that (authentic, and it is
        # the reasoning handle for the column-count step -- not a guess).
        return {"ok": False, "columns": [], "rows": [], "count": 0,
                "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Pages / responses
# ---------------------------------------------------------------------------
_PAGE_CSS = """
:root{
  color-scheme:light dark;
  --bg:#0d1017; --panel:#151a22; --panel2:#1b2230; --line:#273142; --line2:#30465f;
  --ink:#e7edf3; --muted:#8aa0b4; --accent:#3f8cff; --accent2:#5aa0ff;
  --mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
  --ok:#2ea043; --bad:#f85149;
}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink)}
.bar{display:flex;align-items:center;gap:12px;padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
.bar .dot{width:10px;height:10px;border-radius:50%;background:var(--accent)}
.bar b{font-size:15px;letter-spacing:.3px}
.bar .tag{margin-left:auto}
.pill{display:inline-block;background:var(--panel2);border:1px solid var(--line2);border-radius:999px;padding:3px 11px;font:12px var(--mono);color:var(--muted)}
.wrap{max-width:880px;margin:0 auto;padding:34px 20px 60px}
h1{font-size:26px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0}
label{display:block;font-weight:600;margin-bottom:8px}
.row{display:flex;gap:10px;flex-wrap:wrap}
input[type=text]{flex:1 1 320px;min-width:0;padding:12px 14px;border-radius:8px;border:1px solid var(--line2);background:#0b0f14;color:var(--ink);font:14px var(--mono)}
button{padding:11px 22px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
button:hover{background:var(--accent2)}
.muted{color:var(--muted);font-size:14px}
code{font:13px var(--mono);background:#0b0f14;border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.ex{cursor:pointer;border-bottom:1px dotted var(--line2)}
table{width:100%;border-collapse:collapse;margin-top:14px;font:13px var(--mono)}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--panel2);color:var(--muted);font-weight:600}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:13px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:13px var(--mono)}
.err{color:var(--bad)}
a{color:var(--accent2)}
footer{color:var(--muted);font-size:13px;margin-top:26px}
"""

_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quartermaster - Asset Registry</title><style>%(css)s</style></head>
<body>
<div class="bar"><span class="dot"></span><b>QUARTERMASTER</b>
  <span class="muted">internal asset registry</span>
  <span class="tag pill">instance %(fp)s</span></div>
<div class="wrap">
  <h1>Asset lookup</h1>
  <p class="sub">Legacy internal console. Enter an asset tag to pull its inventory record.</p>

  <div class="card">
    <label for="t">Asset tag</label>
    <div class="row">
      <input id="t" type="text" placeholder="AST-1001" value="AST-1001"
             autocomplete="off" spellcheck="false">
      <button id="go">Look up</button>
    </div>
    <p class="muted">Examples:
      <span class="ex" data-t="AST-1001">AST-1001</span>,
      <span class="ex" data-t="AST-1003">AST-1003</span>,
      <span class="ex" data-t="AST-1006">AST-1006</span>.
      The registry holds the company's public inventory.</p>
    <div id="out"></div>
  </div>

  <div class="card">
    <p class="muted"><b>White-box challenge.</b> The full server source is
      <code>challenge/app.py</code> &mdash; the lookup builds its SQL query by
      string concatenation. Regular staff see only the public
      <code>assets</code> inventory; a separate <b>restricted custody
      registry</b> on the same database is not exposed by any endpoint. Its
      table and column names are provisioned per instance by ops and are not
      printed anywhere. Per ops policy the custody record is <b>sealed</b>: the
      flag is stored enciphered and split across two channels, so no single read
      reveals it &mdash; see the custody-cipher in the source.</p>
  </div>

  <footer>Quartermaster &middot; asset registry &middot; instance %(fp)s</footer>
</div>
<script>
const out=document.getElementById('out'), inp=document.getElementById('t');
function render(j){
  if(!j.ok){ out.innerHTML='<pre class="err">query error: '+(j.error||'unknown')+'</pre>'; return; }
  if(!j.rows.length){ out.innerHTML='<pre class="muted">No matching record.</pre>'; return; }
  let h='<table><thead><tr>'+j.columns.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>';
  for(const r of j.rows){ h+='<tr>'+r.map(v=>'<td>'+String(v===null?'':v)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</td>').join('')+'</tr>'; }
  out.innerHTML=h+'</tbody></table>';
}
async function lookup(){
  out.innerHTML='<pre class="muted">looking up...</pre>';
  try{
    const r=await fetch('/lookup?tag='+encodeURIComponent(inp.value));
    render(await r.json());
  }catch(e){ out.innerHTML='<pre class="err">transport error: '+e+'</pre>'; }
}
document.getElementById('go').onclick=lookup;
inp.addEventListener('keydown',e=>{ if(e.key==='Enter') lookup(); });
for(const s of document.querySelectorAll('.ex'))
  s.onclick=()=>{ inp.value=s.dataset.t; lookup(); };
lookup();
</script>
</body></html>
"""


def _json(obj, status=200):
    return status, "application/json; charset=utf-8", json.dumps(obj).encode()


def _html(body, status=200):
    return status, "text/html; charset=utf-8", body.encode()


def _text(body, status=200):
    return status, "text/plain; charset=utf-8", body.encode()


def handle_lookup(query: str):
    params = parse_qs(query, keep_blank_values=True)
    tags = params.get("tag", [])
    if not tags:
        return _json({"ok": False, "columns": [], "rows": [], "count": 0,
                      "error": "missing ?tag= parameter"}, 400)
    return _json(do_lookup(tags[0]))


def route(method: str, path: str, query: str):
    """Backend-agnostic request handler -> (status, content_type, body_bytes)."""
    if method not in ("GET", "HEAD"):
        return _text("method not allowed\n", 405)

    if path in ("/", ""):
        return _html(_INDEX_HTML % {"css": _PAGE_CSS, "fp": FINGERPRINT})

    if path == "/whoami":
        # public, non-secret: instance fingerprint + the one query endpoint.
        # Deliberately leaks NOTHING about the restricted schema.
        return _json({"service": "quartermaster", "fingerprint": FINGERPRINT,
                      "lookup": "/lookup?tag=", "inventory": "assets"})

    if path == "/lookup":
        return handle_lookup(query)

    return _text("404 not found\n", 404)


# ---------------------------------------------------------------------------
# Standard-library http.server backend (zero dependencies)
# ---------------------------------------------------------------------------
def run(host, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self):
            parsed = urlsplit(self.path)
            status, ctype, body = route(self.command, parsed.path, parsed.query)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("quartermaster listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    global PORT
    host = os.environ.get("HOST", "0.0.0.0")
    port = PORT
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
    PORT = port
    run(host, port)


if __name__ == "__main__":
    main()
