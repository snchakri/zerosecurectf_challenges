// pages/api/login.js
// StarkID Agent Authentication Gateway
//
// Issues a signed RS256 identity token to verified S.H.I.E.L.D. field agents.
// Clearance level is encoded in the token payload — only Director-level tokens
// may access classified intelligence endpoints.

import jwt from "jsonwebtoken";
import { privateKey } from "../../lib/keys";

const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const rateLimitState = new Map();

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }

  return req.socket?.remoteAddress ?? "unknown";
}

function getBucket(ip) {
  const now = Date.now();
  const bucket = rateLimitState.get(ip) ?? { attempts: [], lockedUntil: 0 };

  bucket.attempts = bucket.attempts.filter(
    (timestamp) => now - timestamp < ATTEMPT_WINDOW_MS
  );

  if (bucket.lockedUntil && bucket.lockedUntil <= now) {
    bucket.lockedUntil = 0;
  }

  rateLimitState.set(ip, bucket);
  return bucket;
}

function lockResponse(res, bucket) {
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((bucket.lockedUntil - Date.now()) / 1000)
  );

  res.setHeader("Retry-After", String(retryAfterSeconds));
  return res.status(429).json({
    error: "Too many authentication attempts. Try again later.",
    retryAfterSeconds,
  });
}

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const clientIp = getClientIp(req);
  const bucket = getBucket(clientIp);

  if (bucket.lockedUntil > Date.now()) {
    return lockResponse(res, bucket);
  }

  const { agentId, passphrase } = req.body ?? {};

  // Field agents are issued standard Level-1 clearance credentials on intake.
  if (agentId !== "coulson" || passphrase !== "iamironman") {
    bucket.attempts.push(Date.now());

    if (bucket.attempts.length >= MAX_ATTEMPTS) {
      bucket.lockedUntil = Date.now() + LOCKOUT_MS;
      bucket.attempts = [];
      return lockResponse(res, bucket);
    }

    return res.status(401).json({
      error: "Authentication failed. S.H.I.E.L.D. credentials not recognised.",
    });
  }

  bucket.attempts = [];
  bucket.lockedUntil = 0;

  const payload = {
    sub:       agentId,
    clearance: "level-1",       // <– Director clearance required for the flag
    division:  "field-ops",
    iss:       "starkid.stark.tech",
    aud:       "starkid.stark.tech",
  };

  const token = jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "2h",
  });

  return res.status(200).json({
    message: `Welcome back, Agent ${agentId}. Initialising StarkID session.`,
    token,
    clearance: "level-1",
  });
}
