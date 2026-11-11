#!/usr/bin/env node
'use strict';
/*
 * ZSCTF :: Amalgam  (web, Hard)
 *
 * "Amalgam - Workspace Preferences" is a team settings service. A member saves
 * their UI preferences by PATCHing a small JSON document; the server
 * deep-MERGES that patch into their stored profile (hence the name). Merging is
 * the whole product -- and the whole challenge.
 *
 * A prior pentest flagged this merge for PROTOTYPE POLLUTION, so a guard was
 * added. The guard is in this file, in plain sight. It is the kind of fix a
 * team ships under time pressure: it blocks the one key everybody names in the
 * report, and believes the hole is closed.
 *
 * The admin console (/api/flag) does NOT read any stored preference. It builds
 * a FRESH authorization context from first principles and asks that object two
 * questions: are you an admin, and do you carry this workspace's clearance
 * code? A guest's fresh context answers "no" to both. There is no preference,
 * no cookie, and no benign request that turns either answer to "yes" -- the
 * only way those answers flip is if the answer lives not on the object but on
 * the object every object inherits from.
 *
 * The console never hands over the flag whole. Once authorized, it is a per-byte
 * EXPORT STREAM: a manifest (keystream root key + length + verification digest),
 * then one XOR-masked flag byte per request. Which byte is a per-request EXPORT
 * OFFSET -- read off a FRESH context too, so advancing the stream one byte at a
 * time reuses the same prototype pollution. The flag therefore never appears
 * whole in any single response.
 *
 * WHITE-BOX: players are given this exact file. Nothing is hidden by obscurity.
 *
 * Per-instance: ZSCTF_SEED derives a public instance fingerprint, the public
 * per-workspace clearance code, and the (secret) cookie-signing key.
 * ZSCTF_FLAG sets the flag. Same seed -> same instance.
 *
 * Dependency-free: Node 22 built-ins only (http, crypto). `node app.js` serves
 * on $PORT (default 8000).
 */
const http = require('http');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Per-instance configuration (derived deterministically from the team seed).
// Nothing secret is baked into this file: the secrets are functions of the
// seed, which is injected at run time and never shipped to players.
// ---------------------------------------------------------------------------
const SEED = Buffer.from(process.env.ZSCTF_SEED || 'static-demo-seed');
const FLAG = process.env.ZSCTF_FLAG || 'zerosecurectf{pr0t0_p0lluti0n_inherits_the_cr0wn}';

function derive(label, nhex) {
  return crypto.createHash('sha256')
    .update(SEED).update('|').update(label)
    .digest('hex').slice(0, nhex);
}

// PUBLIC, non-secret values (shown to everyone; they prove determinism and
// tell the player which clearance code THIS workspace requires).
const FINGERPRINT = derive('instance-fingerprint', 12);
const REQUIRED_CLEARANCE = 'clr_' + derive('workspace-clearance', 12);

// SECRET: the cookie-signing key. Only used to keep per-member sessions apart;
// it is NOT part of the intended path and is never sent to the client.
const COOKIE_KEY = crypto.createHash('sha256').update(SEED).update('|cookie-key').digest();

// ---------------------------------------------------------------------------
// THE FLAG EXPORT STREAM  (organizer hardening: the flag is NEVER handed over
// whole in a single response). The admin console is not a bulk reveal; it is a
// per-byte export channel driven by the SAME prototype-pollution primitive that
// opens the gate. Each byte of the flag is XOR-masked by a per-instance
// keystream. The keystream's root key (STREAM_KEY) is seed-derived and is
// disclosed ONLY inside the gated export manifest -- so a non-admin never learns
// it, and the flag never travels in cleartext. A truncated digest of the whole
// flag is published in the manifest so a solver can VERIFY a reconstruction and
// reject any decoy/off-by-one result (guess-exposure 0).
// ---------------------------------------------------------------------------
const FLAG_BYTES = Buffer.from(FLAG, 'utf8');
const FLAG_LEN = FLAG_BYTES.length;
// root key for the export keystream; seed-derived (per-instance, deterministic),
// 128-bit, revealed only to an authorized caller inside the manifest.
const STREAM_KEY = derive('flag-stream-key', 32);
// truncated SHA-256 of the whole flag: a verifiable gate for the reconstruction.
const FLAG_DIGEST = crypto.createHash('sha256').update(FLAG_BYTES).digest('hex').slice(0, 16);

function keystreamByte(i) {
  // one keystream byte per flag position, bound to STREAM_KEY and the index.
  return crypto.createHash('sha256')
    .update(STREAM_KEY).update('|').update(String(i >>> 0))
    .digest()[0];
}

// Seed-varying DECOY the manifest advertises as a "cached preview". It is inert:
// it fails the published strict validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$ on
// sight (UPPERCASE body), so a careful solver rejects it by reasoning; it also
// fails the manifest's own digest. It is here to cost the careless time.
const DECOY_PREVIEW = 'zerosecurectf{STREAM_' + FINGERPRINT.toUpperCase() + '}';

const PORT = parseInt(process.env.PORT || '8000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_BODY = 64 * 1024; // 64 KiB cap on a preferences patch

// ---------------------------------------------------------------------------
// In-memory sessions. Purely for realism: a member's saved preferences persist
// across their requests so the dashboard can echo them back. The admin gate
// does not consult them. Sessions are not load-bearing for the challenge.
// ---------------------------------------------------------------------------
const sessions = new Map(); // sid -> { prefs: {...} }

function signSid(sid) {
  const mac = crypto.createHmac('sha256', COOKIE_KEY).update(sid).digest('hex').slice(0, 32);
  return sid + '.' + mac;
}
function verifySid(value) {
  if (typeof value !== 'string' || value.indexOf('.') < 0) return null;
  const dot = value.lastIndexOf('.');
  const sid = value.slice(0, dot);
  const mac = value.slice(dot + 1);
  const expect = crypto.createHmac('sha256', COOKIE_KEY).update(sid).digest('hex').slice(0, 32);
  // constant-time compare on equal-length hex strings
  if (mac.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  return sid;
}
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// ---------------------------------------------------------------------------
// THE DEEP-MERGE  --  this is the sink, and the whole challenge.
//
// Contract: merge a user's JSON preference patch into their profile object,
// recursing into nested objects so a patch can update one deep field without
// clobbering its siblings. Arrays and primitives are treated as leaf values.
//
// HARDENING (added after the pentest): skip the "__proto__" key, which was the
// vector the report called out. The author believes this closes prototype
// pollution. It is in plain sight here that the block names exactly one key.
// ---------------------------------------------------------------------------
function isMergeable(v) {
  // "object-like" for the purpose of recursion: plain objects and functions.
  // (Arrays are leaf values; null is not mergeable.)
  return v !== null && (typeof v === 'object' || typeof v === 'function') && !Array.isArray(v);
}

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue; // <<< THE GUARD >>> blocks exactly one key
    const sVal = source[key];
    const tVal = target[key];
    if (isMergeable(sVal) && isMergeable(tVal)) {
      deepMerge(tVal, sVal); // descend into the EXISTING child (do not clobber)
    } else {
      target[key] = sVal;
    }
  }
  return target;
}

// ---------------------------------------------------------------------------
// THE ADMIN GATE  --  reads a FRESH object, never a stored preference.
//
// A fresh plain object has no own `isAdmin` and no own `clearance`. Reading
// them therefore walks the prototype chain. For a guest instance that yields
// `undefined` for both -> denied. The gate is honest: there is no back door,
// no debug flag, no header. The answers live on the object itself... unless
// someone has changed what every object inherits.
// ---------------------------------------------------------------------------
function authorize() {
  const policy = {}; // fresh, empty authorization context built per request
  return policy.isAdmin === true && policy.clearance === REQUIRED_CLEARANCE;
}

// The export cursor is ALSO read off a FRESH object, exactly like the gate. A
// fresh object has no own `exportOffset`, so the only way to carry one into this
// context is to have changed what every object inherits -- i.e. the SAME
// prototype pollution. Advancing the cursor one byte at a time therefore means
// re-polluting the prototype per byte: the export reuses the crux primitive.
function exportCursor() {
  const ctx = {}; // fresh, empty -- no own exportOffset
  return ctx.exportOffset; // resolves through the prototype chain, if polluted
}

// ---------------------------------------------------------------------------
// HTTP helpers. Response bodies are built on null-prototype objects so a
// polluted Object.prototype does not smear inherited keys into our JSON.
// ---------------------------------------------------------------------------
function sendJson(res, status, obj, extraHeaders) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = Object.assign(
    { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length },
    extraHeaders || {}
  );
  res.writeHead(status, headers);
  res.end(body);
}
function sendHtml(res, status, html) {
  const body = Buffer.from(html);
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length });
  res.end(body);
}
function j(obj) {
  // Defensive hygiene: rebuild the payload on a null-prototype object. Note that
  // JSON.stringify already serialises only OWN enumerable keys (it never walks
  // the prototype), so a polluted Object.prototype does not leak into responses
  // regardless; this is belt-and-braces and documents the intent.
  const clean = Object.create(null);
  for (const k of Object.keys(obj)) clean[k] = obj[k];
  return clean;
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------
const CSS = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e7edf3}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px}
h1{font-size:28px;margin:0 0 4px}
.sub{color:#8aa0b4;margin:0 0 24px}
.card{background:#161b22;border:1px solid #273142;border-radius:12px;padding:20px;margin:18px 0}
label{display:block;font-weight:600;margin-bottom:8px}
textarea,input[type=text]{width:100%;padding:12px 14px;border-radius:8px;border:1px solid #30465f;background:#0b0f14;color:#e7edf3;font:13px ui-monospace,Menlo,Consolas,monospace}
textarea{min-height:120px;resize:vertical}
button{margin-top:12px;padding:11px 20px;border:0;border-radius:8px;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer}
button:hover{background:#4793ff}
button.secondary{background:#30465f}
code,pre{font:13px ui-monospace,Menlo,Consolas,monospace}
pre{background:#0b0f14;border:1px solid #273142;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8aa0b4;font-size:14px}
.pill{display:inline-block;background:#0b0f14;border:1px solid #30465f;border-radius:999px;padding:3px 10px;font:12px ui-monospace,monospace;color:#9fb3c8;margin-right:6px}
a{color:#58a6ff}
`;

function indexHtml() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Amalgam - Workspace Preferences</title><style>${CSS}</style></head>
<body><div class="wrap">
  <h1>Amalgam</h1>
  <p class="sub">Workspace Preferences &mdash; save a preference patch and we merge it into your profile.</p>
  <span class="pill">instance ${FINGERPRINT}</span>
  <span class="pill">clearance ${REQUIRED_CLEARANCE}</span>

  <div class="card">
    <label for="patch">Preference patch (JSON)</label>
    <textarea id="patch">{"theme":"dark","layout":{"density":"compact"}}</textarea>
    <button id="save">Save preferences</button>
    <button id="admin" class="secondary">Open admin console</button>
    <p class="muted">Your patch is deep-merged into your stored profile. Nested
      objects merge field-by-field. After a pentest we added a guard against
      prototype pollution.</p>
    <pre id="out" class="muted">Result will appear here.</pre>
  </div>

  <div class="card">
    <p class="muted"><b>Admin console.</b> <code>GET /api/flag</code> authorizes by
      building a fresh policy context and checking it is an admin carrying this
      workspace's clearance code (<code>${REQUIRED_CLEARANCE}</code>). Guests are
      denied. The console reads <i>no</i> stored preference. It never returns the
      flag whole: an authorized caller gets a <b>per-byte export stream</b>
      (a manifest, then one masked byte per request, selected by an export offset
      that is itself read off a fresh context).</p>
    <p class="muted"><b>White-box challenge.</b> The full server source is
      <code>challenge/app.js</code>. The merge, its guard, and the gate are all
      in plain sight. Endpoints: <code>/whoami</code>, <code>/api/me</code>,
      <code>POST /api/preferences</code>, <code>GET /api/flag</code>.</p>
  </div>

<script>
const out=document.getElementById('out');
const patch=document.getElementById('patch');
async function show(p){out.textContent='working...';try{const r=await p;out.textContent=JSON.stringify(await r.json(),null,2);}catch(e){out.textContent='error: '+e;}}
document.getElementById('save').onclick=()=>show(fetch('/api/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:patch.value}));
document.getElementById('admin').onclick=()=>show(fetch('/api/flag'));
</script>
</div></body></html>`;
}

// ---------------------------------------------------------------------------
// Request handling. Routing is by explicit path comparison (never an object
// lookup) so a polluted prototype cannot conjure a route.
// ---------------------------------------------------------------------------
function getSession(req, res) {
  const cookies = parseCookies(req.headers['cookie']);
  let sid = verifySid(cookies['amalgam_sid']);
  if (!sid) {
    sid = crypto.randomBytes(16).toString('hex');
    res.setHeader('Set-Cookie',
      'amalgam_sid=' + encodeURIComponent(signSid(sid)) + '; Path=/; HttpOnly; SameSite=Lax');
  }
  let s = sessions.get(sid);
  if (!s) { s = { prefs: {} }; sessions.set(sid, s); }
  return s;
}

function readBody(req, limit, cb) {
  let size = 0;
  const chunks = [];
  let done = false;
  req.on('data', (c) => {
    if (done) return;
    size += c.length;
    if (size > limit) { done = true; cb(new Error('body too large')); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => { if (!done) { done = true; cb(null, Buffer.concat(chunks)); } });
  req.on('error', (e) => { if (!done) { done = true; cb(e); } });
}

function handlePreferences(req, res) {
  const s = getSession(req, res);
  readBody(req, MAX_BODY, (err, buf) => {
    if (err) return sendJson(res, 413, j({ ok: false, reason: 'request body too large (max 64 KiB)' }));
    let patch;
    try {
      patch = JSON.parse(buf.length ? buf.toString('utf8') : '{}');
    } catch (e) {
      return sendJson(res, 400, j({ ok: false, reason: 'invalid JSON' }));
    }
    if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) {
      return sendJson(res, 400, j({ ok: false, reason: 'preference patch must be a JSON object' }));
    }
    // THE SINK: deep-merge the user's patch into their stored profile.
    deepMerge(s.prefs, patch);
    // Echo the stored profile's OWN keys back (JSON.stringify never serialises
    // inherited keys, so a landed pollution will NOT show up here -- confirm it
    // instead via GET /api/me, whose `authorized` field runs the real gate).
    return sendJson(res, 200, { ok: true, prefs: s.prefs });
  });
}

function server() {
  return http.createServer((req, res) => {
    let pathname = '/';
    try { pathname = new URL(req.url, 'http://localhost').pathname; } catch (_) {}
    const method = req.method || 'GET';

    if (method === 'GET' && (pathname === '/' || pathname === '')) {
      return sendHtml(res, 200, indexHtml());
    }
    if (method === 'GET' && pathname === '/whoami') {
      // public, non-secret: proves determinism and tells tooling the clearance
      // code and port for this instance.
      return sendJson(res, 200, j({
        service: 'amalgam',
        fingerprint: FINGERPRINT,
        required_clearance: REQUIRED_CLEARANCE,
        port: PORT
      }));
    }
    if (method === 'GET' && pathname === '/api/me') {
      const s = getSession(req, res);
      // `authorized` runs the real gate so a player gets immediate feedback.
      return sendJson(res, 200, { ok: true, prefs: s.prefs, authorized: authorize() });
    }
    if (method === 'POST' && pathname === '/api/preferences') {
      return handlePreferences(req, res);
    }
    if (method === 'GET' && pathname === '/api/flag') {
      if (!authorize()) {
        return sendJson(res, 403, j({
          ok: false,
          reason: 'forbidden: admin console requires an admin context carrying clearance ' + REQUIRED_CLEARANCE
        }));
      }
      // AUTHORIZED. This console is a per-byte export stream, never a bulk
      // reveal: the flag is never returned whole in any single response.
      const cur = exportCursor();
      if (!Number.isInteger(cur) || cur < 0 || cur >= FLAG_LEN) {
        // No valid export offset in context yet -> emit the MANIFEST only. It
        // carries the keystream root key, the total length and a verification
        // digest, plus a decoy preview. It carries NO flag bytes.
        return sendJson(res, 200, j({
          ok: true,
          stream: true,
          length: FLAG_LEN,
          stream_key: STREAM_KEY,
          digest: FLAG_DIGEST,
          cache_preview: DECOY_PREVIEW,
          note: 'authorized. export one masked byte per request: set an integer '
              + 'export offset on your authorization context (0-based, 0 <= offset '
              + '< length) and re-request. each response returns mask = flag[offset] '
              + 'XOR keystream(offset), where keystream(offset) = '
              + 'SHA-256(stream_key | "|" | offset)[0]. reassemble all offsets and '
              + 'verify SHA-256(flag)[:16] == digest.'
        }));
      }
      // A valid offset is in context -> return EXACTLY ONE masked byte.
      const masked = FLAG_BYTES[cur] ^ keystreamByte(cur);
      return sendJson(res, 200, j({
        ok: true,
        length: FLAG_LEN,
        offset: cur,
        mask: masked.toString(16).padStart(2, '0')
      }));
    }
    return sendJson(res, 404, j({ ok: false, reason: 'not found' }));
  });
}

function main() {
  let port = PORT;
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && i + 1 < args.length) port = parseInt(args[i + 1], 10);
  }
  const srv = server();
  srv.listen(port, HOST, () => {
    process.stderr.write('amalgam listening on ' + HOST + ':' + port + '\n');
  });
}

if (require.main === module) main();

module.exports = {
  deepMerge, authorize, exportCursor, keystreamByte,
  REQUIRED_CLEARANCE, FINGERPRINT, STREAM_KEY, FLAG_LEN, FLAG_DIGEST
};
