// pages/index.js  — StarkID Agent Portal
import { useState } from "react";

const gold   = "#f0b232";
const red    = "#c0392b";
const silver = "#aab0bb";

const s = {
  root:  { fontFamily: "'Courier New', monospace", background: "#0a0c10", color: "#d0d8e4", minHeight: "100vh", padding: "2rem" },
  wrap:  { maxWidth: 680, margin: "0 auto" },
  logo:  { display: "flex", alignItems: "center", gap: 14, marginBottom: "1.5rem" },
  arc:   { width: 48, height: 48, borderRadius: "50%", background: "radial-gradient(circle, #7ec8e3 0%, #005f7f 60%, #001a22 100%)", boxShadow: "0 0 18px #7ec8e388", flexShrink: 0 },
  h1:    { color: gold, margin: 0, fontSize: "1.4rem", fontWeight: "bold", letterSpacing: 2, textTransform: "uppercase" },
  sub:   { color: silver, fontSize: "0.75rem", margin: "2px 0 0", letterSpacing: 1 },
  divider: { borderColor: "#1e2530", margin: "1.5rem 0" },
  card:  { border: `1px solid #1e2a3a`, borderRadius: 6, padding: "1.5rem", marginBottom: "1.25rem", background: "#0d1117" },
  ch:    { color: gold, fontSize: "0.8rem", letterSpacing: 2, textTransform: "uppercase", margin: "0 0 12px", borderBottom: "1px solid #1e2a3a", paddingBottom: 8 },
  label: { color: silver, fontSize: "0.75rem", display: "block", marginBottom: 4, letterSpacing: 1 },
  input: { display: "block", width: "100%", marginBottom: 10, background: "#070b10", border: "1px solid #1e2a3a", color: "#d0d8e4", padding: "8px 12px", borderRadius: 4, fontFamily: "monospace", boxSizing: "border-box" },
  btn:   { background: gold, color: "#000", border: "none", padding: "8px 22px", borderRadius: 4, cursor: "pointer", fontFamily: "monospace", fontWeight: "bold", letterSpacing: 1, fontSize: "0.8rem" },
  pre:   { background: "#070b10", border: "1px solid #1e2a3a", borderRadius: 4, padding: "1rem", overflowX: "auto", fontSize: "0.8rem", margin: "1.25rem 0 0" },
  link:  { color: "#4a9fd4", textDecoration: "none", fontSize: "0.8rem" },
  tag:   { display: "inline-block", background: "#0d1a2a", color: "#4a9fd4", border: "1px solid #1e3a5a", borderRadius: 3, padding: "2px 8px", fontSize: "0.7rem", marginRight: 6 },
};

export default function StarkID() {
  const [agentId,    setAgentId]    = useState("coulson");
  const [passphrase, setPassphrase] = useState("");
  const [bearer,     setBearer]     = useState("");
  const [out,        setOut]        = useState(null);
  const [isErr,      setIsErr]      = useState(false);

  const call = async (url, opts = {}) => {
    setOut(null);
    const res  = await fetch(url, opts);
    const data = await res.json();
    setIsErr(!res.ok);
    setOut(JSON.stringify(data, null, 2));
  };

  return (
    <div style={s.root}>
      <div style={s.wrap}>

        {/* Logo */}
        <div style={s.logo}>
          <div style={s.arc} />
          <div>
            <h1 style={s.h1}>StarkID</h1>
            <p style={s.sub}>Stark Industries · Agent Identity Gateway · v3.1</p>
          </div>
        </div>

        <div style={{ marginBottom: "1.5rem" }}>
          {["RS256 Signed Tokens", "JWKS Federation", "Level-10 Clearance"].map(t => (
            <span key={t} style={s.tag}>{t}</span>
          ))}
        </div>

        {/* Login */}
        <div style={s.card}>
          <p style={s.ch}>Step 1 — Agent Authentication</p>
          <label style={s.label}>AGENT ID</label>
          <input style={s.input} value={agentId} onChange={e => setAgentId(e.target.value)} />
          <label style={s.label}>PASSPHRASE</label>
          <input style={s.input} type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="S.H.I.E.L.D. passphrase" />
          <button style={s.btn} onClick={() => call("/api/login", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ agentId, passphrase }),
          })}>
            AUTHENTICATE
          </button>
        </div>

        {/* Flag */}
        <div style={s.card}>
          <p style={s.ch}>Step 2 — Retrieve Classified Intel (Director Only)</p>
          <label style={s.label}>STARKID TOKEN</label>
          <input style={s.input} value={bearer} onChange={e => setBearer(e.target.value)} placeholder="Paste StarkID JWT" />
          <button style={s.btn} onClick={() => call("/api/flag", {
            headers: { Authorization: `Bearer ${bearer}` },
          })}>
            REQUEST INTEL
          </button>
        </div>

        {/* Output */}
        {out && (
          <pre style={{ ...s.pre, color: isErr ? "#e05555" : "#4dca88" }}>{out}</pre>
        )}

        <hr style={s.divider} />
        <p>
          <a style={s.link} href="/api/.well-known/jwks" target="_blank">
            ↗ StarkTech Public Verification Keys (JWKS)
          </a>
          <span style={{ color: "#333", margin: "0 8px" }}>·</span>
          <span style={{ color: "#333", fontSize: "0.75rem" }}>J.A.R.V.I.S. Token Verification Engine</span>
        </p>
      </div>
    </div>
  );
}
