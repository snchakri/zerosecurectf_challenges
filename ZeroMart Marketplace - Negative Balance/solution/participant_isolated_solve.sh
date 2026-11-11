#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARTICIPANT_DIR="$ROOT_DIR/participant_deliverables"
BIN_PATH="$PARTICIPANT_DIR/zeromart"
README_PATH="$PARTICIPANT_DIR/README.md"
SHA_PATH="$PARTICIPANT_DIR/zeromart.sha256"

if [[ ! -f "$BIN_PATH" || ! -f "$README_PATH" || ! -f "$SHA_PATH" ]]; then
    echo "Participant deliverables incomplete."
    echo "Run: make -C $ROOT_DIR/host package"
    exit 1
fi

echo "[test] Checking participant deliverables contain only expected files..."
mapfile -t files < <(find "$PARTICIPANT_DIR" -maxdepth 1 -type f -printf "%f\n" | sort)
expected=("README.md" "zeromart" "zeromart.sha256")

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

cp "$BIN_PATH" "$SANDBOX_DIR/zeromart"
cp "$README_PATH" "$SANDBOX_DIR/README.md"
cp "$SHA_PATH" "$SANDBOX_DIR/zeromart.sha256"

(
    cd "$SANDBOX_DIR"
    sha256sum -c zeromart.sha256 >/dev/null
    SOLVE_OUTPUT="$(printf "3\n-10000\n6\n7\n" | ./zeromart)"
    echo "$SOLVE_OUTPUT" | grep -q "FLAG UNLOCKED!"
    echo "$SOLVE_OUTPUT" | grep -q "ZeroSecure_CTF{"
)

echo "[ok] Participant-isolated solve passed."
