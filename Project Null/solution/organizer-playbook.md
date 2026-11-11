# Organizer Playbook

## Pre-Launch

1. Run layer lint: `python organizer_host/tools/lint/layer_lint.py`
2. Run export: `python organizer_host/tools/export/export_runtime.py`
3. Start stack: `docker compose -f ops/docker-compose.yml up --build`
4. Run tester smoke flow before event opens.

## Live Operations

1. Monitor backend logs for token errors, false-positive spikes, and 429 rates.
2. Keep immutable copies of exported manifest and compiled artifacts.
3. Do not patch organizer-host keys during live play; use controlled release procedure.

## Incident Response

1. If backend compromise suspected: rotate secret key and restart backend.
2. If artifact mismatch detected: stop backend, regenerate export, verify checksums, redeploy.
3. If persistent load lock: enable load-shedding and extend activation windows temporarily by policy.
