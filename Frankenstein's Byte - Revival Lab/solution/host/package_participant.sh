#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_PATH="$SCRIPT_DIR/build/frankensteins_byte"
PARTICIPANT_DIR="$ROOT_DIR/participant_deliverables"
PARTICIPANT_README_SRC="$ROOT_DIR/docs_host/participant_README.md"
ARCHIVE_PATH="$SCRIPT_DIR/ch3_frankensteins_byte_participant.tar.gz"

if [[ ! -f "$BIN_PATH" ]]; then
    echo "Binary missing: $BIN_PATH"
    echo "Run: make -C $SCRIPT_DIR build"
    exit 1
fi

if [[ ! -f "$PARTICIPANT_README_SRC" ]]; then
    echo "Participant README source missing: $PARTICIPANT_README_SRC"
    exit 1
fi

mkdir -p "$PARTICIPANT_DIR"
cp "$BIN_PATH" "$PARTICIPANT_DIR/frankensteins_byte"
cp "$PARTICIPANT_README_SRC" "$PARTICIPANT_DIR/README.md"

(
    cd "$PARTICIPANT_DIR"
    sha256sum frankensteins_byte > frankensteins_byte.sha256
)

rm -f "$ARCHIVE_PATH"
(
    cd "$ROOT_DIR"
    tar -czf "$ARCHIVE_PATH" participant_deliverables
)

echo "Participant deliverables refreshed in: $PARTICIPANT_DIR"
echo "Participant archive created at: $ARCHIVE_PATH"
