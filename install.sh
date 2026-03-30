#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Pwner - Build & Install Script
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[1;31m'
GRN='\033[1;32m'
BLU='\033[1;34m'
BOLD='\033[1m'
RST='\033[0m'

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
err()   { echo -e "${RED}[-]${RST} $1"; }

PREFIX="${1:-/usr/local}"
BUILD_DIR="build"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$SCRIPT_DIR"

info "Building Pwner..."

# Clean stale cache (avoids cross-machine path mismatch)
rm -rf "$BUILD_DIR/CMakeCache.txt" "$BUILD_DIR/CMakeFiles"

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" 2>&1

# Build
cmake --build . -j"$(nproc)" 2>&1

ok "Build successful!"

echo ""
info "Installing to ${PREFIX}/bin/Pwner ..."

# Install (may need sudo)
if [ -w "${PREFIX}/bin" ] 2>/dev/null; then
    cmake --install . 2>&1
    ok "Installed: ${PREFIX}/bin/Pwner"
else
    info "Root access required for installation to ${PREFIX}/bin"
    sudo cmake --install . 2>&1
    ok "Installed: ${PREFIX}/bin/Pwner"
fi

echo ""
# Verify
if command -v Pwner >/dev/null 2>&1; then
    ok "Pwner is ready! Run: Pwner --help"
else
    info "Make sure ${PREFIX}/bin is in your PATH"
    info "  export PATH=\"${PREFIX}/bin:\$PATH\""
fi
