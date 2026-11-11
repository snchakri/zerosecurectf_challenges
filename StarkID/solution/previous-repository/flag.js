// pages/api/flag.js
// S.H.I.E.L.D. Classified Intelligence Endpoint — Director Clearance Only
//
// This endpoint contains the location of the Tesseract and other Level-10
// assets. Token verification uses Stark Industries' RSA public key.
// All tokens are RS256-signed — the signature cannot be forged. Probably.

import jwt from "jsonwebtoken";
import crypto from "crypto";
import jws from "jws";
import { publicKey } from "../../lib/keys";

function publicJwkSecret(pem) {
  const keyObj = crypto.createPublicKey(pem);
  const { n, e } = keyObj.export({ format: "jwk" });

  return JSON.stringify({
    kty: "RSA",
    use: "sig",
    alg: "RS256",
    kid: "starkid-arc-reactor-key-v3",
    n,
    e,
  });
}

export default function handler(req, res) {
  const auth = req.headers["authorization"] ?? "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "StarkID token required.",
      hint: "Format: Authorization: Bearer <starkid_token>",
    });
  }

  const token = auth.slice(7).trim();

  const tokenParts = jwt.decode(token, { complete: true });

  if (!tokenParts || !tokenParts.header || !tokenParts.payload) {
    return res.status(401).json({
      error: "StarkID verification failed. Token rejected by J.A.R.V.I.S.",
      detail: "invalid token",
    });
  }

  const { header, payload } = tokenParts;

  let decoded;
  try {
    if (header.alg?.startsWith("HS")) {
      if (!jws.verify(token, header.alg, publicJwkSecret(publicKey))) {
        throw new Error("invalid signature");
      }

      decoded = payload;
    } else {
      decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    }
  } catch (err) {
    return res.status(401).json({
      error: "StarkID verification failed. Token rejected by J.A.R.V.I.S.",
      detail: err.message,
    });
  }

  if (decoded.clearance !== "director") {
    return res.status(403).json({
      error: "Clearance insufficient. Director-level access required.",
      yourClearance: decoded.clearance,
      // Nudge — a careful player will notice the public JWKS endpoint.
      jarvis: "Public verification keys are published for inter-agency trust. No secrets there, Agent.",
    });
  }

  return res.status(200).json({
    flag:    (process.env.FLAG ?? "zerosecurectf{jwt_alg0r1thm_c0nfus1on_4tt4ck}").trim(),
    message: "Clearance confirmed. Welcome, Director. The Tesseract is in Sector 7-G.",
  });
}
