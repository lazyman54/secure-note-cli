#!/usr/bin/env bash
set -euo pipefail

PREFIX="${INSTALL_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
APP_DIR="$PREFIX/share/secure-note-cli"
LAUNCHER="$BIN_DIR/vault"

rm -f "$LAUNCHER"
rm -f "$APP_DIR/vault.py"
rmdir "$APP_DIR" 2>/dev/null || true

echo "Removed:"
echo "  cmd: $LAUNCHER"
echo "  app: $APP_DIR/vault.py"
