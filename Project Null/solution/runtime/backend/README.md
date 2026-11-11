# Participant Backend

Run with virtual environment active:

```powershell
.\.venv\Scripts\python.exe participant\backend\run.py
```

Primary routes:
- GET /api/session/bootstrap
- GET /api/progress
- GET /api/layer/{layer}
- POST /api/layer/{layer}/activate
- POST /api/submit-layer
- POST /api/finalize

This backend loads compiled challenge artifacts from `app/challenge_data` and verifies file checksums at startup.
