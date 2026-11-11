#!/usr/bin/env python3
"""
ROBOTS OF THE APOCALYPSE - Flask app.

Three nested dead ends:
  * robots.txt disallows a hidden admin path -> BAIT
  * /record?id= is IDOR-able; walking ids hits a "classified" row -> EARNED-FAKE
  * every 404 carries the EGG, in an HTML comment and the X-Bunker-Status header

Decoy strings (LOCKED):
  bait        : DOOM{r0b0ts_txt_s3cr3t}
  earned-fake : DOOM{1d0r_cl4ss1f13d_0m3g4}
  egg         : "STATUS: bunker sealed . occupants: 0 . flags: 0"
"""
from flask import Flask, Response, render_template, request, abort

app = Flask(__name__)

BAIT = "DOOM{r0b0ts_txt_s3cr3t}"
EARNED_FAKE = "DOOM{1d0r_cl4ss1f13d_0m3g4}"
EGG = "STATUS: bunker sealed . occupants: 0 . flags: 0"

HIDDEN_ADMIN = "/admin_7f3a9c"   # disallowed in robots.txt

# "Database". The user is only ever shown their own rows (1-3) in the UI.
# Row 1337 is CLASSIFIED and reachable only by tampering with ?id= (IDOR).
RECORDS = {
    1: {"owner": "you",   "label": "ration log",        "body": "beans: 4 cans."},
    2: {"owner": "you",   "label": "water log",         "body": "cistern at 12%."},
    3: {"owner": "you",   "label": "duty roster",       "body": "you. just you."},
    42: {"owner": "ops",  "label": "comms check",       "body": "no reply from surface."},
    1337: {"owner": "CMD", "label": "CLASSIFIED",
           "body": f"AUTHORIZATION ARCHIVE: {EARNED_FAKE}"},
}


@app.route("/")
def index():
    mine = {i: RECORDS[i] for i in (1, 2, 3)}
    return render_template("index.html", records=mine)


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        f"Disallow: {HIDDEN_ADMIN}\n"
        "Disallow: /record\n"
    )
    return Response(body, mimetype="text/plain")


@app.route(HIDDEN_ADMIN)
def hidden_admin():
    return render_template("admin.html", bait=BAIT)


@app.route("/record")
def record():
    try:
        rid = int(request.args.get("id", ""))
    except ValueError:
        abort(400)
    rec = RECORDS.get(rid)
    if rec is None:
        abort(404)
    return render_template("record.html", rid=rid, rec=rec)


@app.errorhandler(404)
def not_found(_e):
    html = render_template("404.html", egg=EGG)
    resp = Response(html, status=404)
    resp.headers["X-Bunker-Status"] = EGG
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
