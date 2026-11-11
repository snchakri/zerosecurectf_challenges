#!/usr/bin/env bash
set -euo pipefail

BIN_PATH="${1:-}"

if [[ -z "$BIN_PATH" ]]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

if [[ ! -f "$BIN_PATH" ]]; then
    echo "Binary not found: $BIN_PATH"
    exit 1
fi

echo "[verify] Binary: $BIN_PATH"

if readelf -h "$BIN_PATH" | grep -Eq "Type:[[:space:]]+EXEC"; then
    echo "[ok] PIE disabled (ELF type EXEC)."
else
    echo "[fail] PIE appears enabled (expected Type EXEC)."
    exit 1
fi

if readelf -s "$BIN_PATH" | grep -q "__stack_chk_fail"; then
    echo "[fail] Stack canary symbol found (__stack_chk_fail)."
    exit 1
else
    echo "[ok] Stack canary appears disabled."
fi

STACK_FLAGS="$(readelf -W -l "$BIN_PATH" | awk '/GNU_STACK/{print $(NF-1)}')"
if [[ "$STACK_FLAGS" == *"E"* ]]; then
    echo "[ok] Executable stack enabled (GNU_STACK has execute flag)."
else
    echo "[fail] Executable stack is not enabled (expected execute flag)."
    exit 1
fi

if command -v checksec >/dev/null 2>&1; then
    echo "[info] checksec summary (secondary visibility):"
    checksec --file="$BIN_PATH" || true
else
    echo "[info] checksec not found; skipping secondary checksec report."
fi

echo "[verify] All required mitigation states match plan."
