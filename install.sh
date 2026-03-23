#!/usr/bin/env bash
set -euo pipefail

REPO="zhizhuodemao/trace-ui-for-ai"
VERSION="v0.1.0"
BIN_NAME="trace-cli"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS-$ARCH" in
    Darwin-arm64)  TARGET="aarch64-apple-darwin" ;;
    Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
    Linux-x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    Linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *) err "Unsupported platform: $OS-$ARCH" ;;
esac

info "Platform: $OS $ARCH ($TARGET)"

# Check if pre-built binary is available
RELEASE_URL="https://github.com/$REPO/releases/download/$VERSION/${BIN_NAME}-${TARGET}"
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

info "Trying to download pre-built binary..."
if curl -fSL "$RELEASE_URL" -o "$INSTALL_DIR/$BIN_NAME" 2>/dev/null; then
    chmod +x "$INSTALL_DIR/$BIN_NAME"
    ok "Downloaded pre-built binary to $INSTALL_DIR/$BIN_NAME"
else
    info "No pre-built binary available, building from source..."

    if ! command -v cargo &>/dev/null; then
        err "Rust not found. Install from https://rustup.rs/"
    fi

    info "Building with cargo (this may take a minute)..."
    cargo build --release --quiet
    cp target/release/$BIN_NAME "$INSTALL_DIR/$BIN_NAME"
    ok "Built and installed to $INSTALL_DIR/$BIN_NAME"
fi

# Download example trace
EXAMPLE_URL="https://github.com/$REPO/releases/download/$VERSION/example.trace.gz"
EXAMPLE_DIR="$(pwd)"

if [ ! -f "$EXAMPLE_DIR/example.trace" ]; then
    info "Downloading example trace..."
    if curl -fSL "$EXAMPLE_URL" -o /tmp/example.trace.gz 2>/dev/null; then
        gunzip -f /tmp/example.trace.gz
        mv /tmp/example.trace "$EXAMPLE_DIR/example.trace"
        ok "Example trace downloaded to $EXAMPLE_DIR/example.trace"
    else
        info "Example trace not available (you can generate your own with unidbg)"
    fi
else
    info "Example trace already exists"
fi

# Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    info "Add this to your shell profile (~/.zshrc or ~/.bashrc):"
    echo ""
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
fi

echo ""
ok "Installation complete!"
echo ""
echo "  Quick start:"
echo "    trace-cli example.trace info"
echo "    trace-cli example.trace search \"0x67452301\""
echo "    trace-cli example.trace lines 13580-13600"
echo "    trace-cli example.trace taint x0@last --data-only"
echo ""
