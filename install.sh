#!/usr/bin/env bash
set -euo pipefail

SOURCE="${BASH_SOURCE:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
PREFIX="${INSTALL_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
APP_DIR="$PREFIX/share/secure-note-cli"
LAUNCHER="$BIN_DIR/vault"
REF="${VAULT_REF:-main}"
REPO="${VAULT_REPO:-}"

mkdir -p "$BIN_DIR" "$APP_DIR"
if [ -f "$SCRIPT_DIR/vault.py" ]; then
  install -m 755 "$SCRIPT_DIR/vault.py" "$APP_DIR/vault.py"
else
  if [ -z "$REPO" ]; then
    echo "Error: vault.py not found locally, and VAULT_REPO is not set." >&2
    echo "Example: VAULT_REPO=\"owner/secure-note-cli\" bash install.sh" >&2
    exit 1
  fi
  URL="https://raw.githubusercontent.com/$REPO/$REF/vault.py"
  curl -fsSL "$URL" -o "$APP_DIR/vault.py"
  chmod 755 "$APP_DIR/vault.py"
fi

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
python3 "$APP_DIR/vault.py" "\$@"
EOF
chmod +x "$LAUNCHER"

echo "Installed:"
echo "  app: $APP_DIR/vault.py"
echo "  cmd: $LAUNCHER"

case ":$PATH:" in
  *":$BIN_DIR:"*)
    echo "PATH already contains $BIN_DIR"
    ;;
  *)
    echo
    echo "Add this to your shell profile (~/.zshrc or ~/.bashrc):"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
