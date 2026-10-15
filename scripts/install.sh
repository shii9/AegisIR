#!/usr/bin/env bash
# Non-root per-user installation, no sudo or package-manager changes.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v go >/dev/null || { echo 'Go 1.23+ is required';exit 1; }
command -v python3 >/dev/null || { echo 'Python 3.10+ is required';exit 1; }
mkdir -p "$HOME/.local/opt/aegisir/python" "$HOME/.local/bin"
CGO_ENABLED=0 go build -trimpath -o "$HOME/.local/opt/aegisir/aegisir" ./cmd/aegisir
cp python/engine.py "$HOME/.local/opt/aegisir/python/engine.py"
ln -sf "$HOME/.local/opt/aegisir/aegisir" "$HOME/.local/bin/aegisir"

# Ensure ~/.local/bin is in PATH in ~/.bashrc if not already present
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  if [ -f "$HOME/.bashrc" ] && ! grep -q '\.local/bin' "$HOME/.bashrc"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  fi
fi

cat <<MSG
✓ Successfully installed to ~/.local/opt/aegisir
✓ Linked to ~/.local/bin/aegisir

You can now run:
  aegisir -help
  aegisir -cases
  aegisir -show
  aegisir -verify
  aegisir -process
  aegisir -all -o report.html
MSG
