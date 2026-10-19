#!/bin/sh
# Install PermitTrace as a Claude Code PreToolUse and PermissionRequest hook.
# Existing settings are copied to a .bak file before they are merged.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$ROOT"

if command -v permittrace >/dev/null 2>&1; then
  BIN=$(command -v permittrace)
elif [ -x "$ROOT/permittrace" ]; then
  BIN=$ROOT/permittrace
else
  echo "building permittrace..."
  go build -o "$ROOT/permittrace" ./cmd/permittrace
  BIN=$ROOT/permittrace
fi

exec "$BIN" install "$@"
