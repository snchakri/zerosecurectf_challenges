#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARTICIPANT_DIR="$ROOT_DIR/participant_deliverables"
BIN_PATH="$PARTICIPANT_DIR/frankensteins_byte"
README_PATH="$PARTICIPANT_DIR/README.md"
SHA_PATH="$PARTICIPANT_DIR/frankensteins_byte.sha256"

if [[ ! -f "$BIN_PATH" || ! -f "$README_PATH" || ! -f "$SHA_PATH" ]]; then
    echo "Participant deliverables incomplete."
    echo "Run: make -C $ROOT_DIR/host package"
    exit 1
fi

echo "[test] Checking participant deliverables contain only expected files..."
mapfile -t files < <(find "$PARTICIPANT_DIR" -maxdepth 1 -type f -printf "%f\n" | sort)
expected=("README.md" "frankensteins_byte" "frankensteins_byte.sha256")

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

cp "$BIN_PATH" "$SANDBOX_DIR/frankensteins_byte"
cp "$README_PATH" "$SANDBOX_DIR/README.md"
cp "$SHA_PATH" "$SANDBOX_DIR/frankensteins_byte.sha256"

(
    cd "$SANDBOX_DIR"
    sha256sum -c frankensteins_byte.sha256 >/dev/null

    python3 - <<'PY'
import subprocess
import sys

completed = subprocess.run(
    ["./frankensteins_byte"],
    input=b"A" * 32 + b"\x05",
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=5,
    check=False,
)
out = completed.stdout.decode("latin-1", errors="replace")

required = [
    "[lab] Gate value now: 0x00000005",
    "[+] Reanimation successful.",
    "ZeroSecure_CTF{frankensteins_byte_lsb_awakened}",
]
for token in required:
    if token not in out:
        sys.stderr.write(out)
        raise SystemExit(f"sandbox solve markers missing: {token}")
PY
)

echo "[ok] Participant-isolated solve passed."
