#!/usr/bin/env bash
set -euo pipefail

# naptrace installer
# Usage: curl -sSL https://raw.githubusercontent.com/hamzamiladin/naptrace/main/install.sh | sh

REPO="hamzamiladin/naptrace"
INSTALL_DIR="${NAPTRACE_INSTALL_DIR:-$HOME/.naptrace/bin}"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="unknown-linux-gnu" ;;
    Darwin) PLATFORM="apple-darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64)  TARGET="x86_64-$PLATFORM" ;;
    aarch64|arm64) TARGET="aarch64-$PLATFORM" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest release tag
echo "Fetching latest release..."
LATEST=$(curl -sI "https://github.com/$REPO/releases/latest" | grep -i location | sed 's/.*tag\///' | tr -d '\r\n')

if [ -z "$LATEST" ]; then
    echo "Could not determine latest release. Install from source:"
    echo "  cargo install naptrace"
    exit 1
fi

echo "Installing naptrace $LATEST for $TARGET..."

# Download binary
URL="https://github.com/$REPO/releases/download/$LATEST/naptrace-$TARGET"
mkdir -p "$INSTALL_DIR"

if command -v curl &>/dev/null; then
    curl -sSL "$URL" -o "$INSTALL_DIR/naptrace"
elif command -v wget &>/dev/null; then
    wget -q "$URL" -O "$INSTALL_DIR/naptrace"
else
    echo "Neither curl nor wget found. Install from source:"
    echo "  cargo install naptrace"
    exit 1
fi

chmod +x "$INSTALL_DIR/naptrace"

echo "Installed to $INSTALL_DIR/naptrace"

# Add to PATH hint
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Add naptrace to your PATH:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    echo "Or add this to your shell profile (~/.bashrc, ~/.zshrc, etc.)"
fi

echo ""
echo "Run 'naptrace doctor' to verify your setup."
