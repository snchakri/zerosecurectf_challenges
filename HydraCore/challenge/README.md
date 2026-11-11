# HydraCore — Directive 9-A

H.Y.D.R.A. forwards mission status to a supplied webhook URL. An internal node behind that relay holds the mission artifact. Map the relay workflow and recover the flag.

Start at `POST /api/relay` with `{ missionId, webhookUrl, proof? }`. The published `/api/internal/briefing` route is a decoy.
