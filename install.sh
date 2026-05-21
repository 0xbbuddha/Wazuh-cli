#!/usr/bin/env bash
set -euo pipefail

REPO="0xbbuddha/wazuh-cli"
BIN_NAME="wazuh-cli"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

die() { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) die "Unsupported OS: $OS" ;;
esac

# Fetch latest release tag
info "Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -n "$LATEST" ] || die "Could not determine latest release"
info "Latest release: $LATEST"

VERSION="${LATEST#v}"
ARCHIVE="${BIN_NAME}_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${LATEST}"

# Download archive and checksum
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "Downloading $ARCHIVE ..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/${BIN_NAME}_${VERSION}_checksums.txt" -o "${TMP}/checksums.txt"

# Verify checksum
info "Verifying checksum..."
cd "$TMP"
grep "$ARCHIVE" checksums.txt | sha256sum -c - || die "Checksum verification failed"
cd - > /dev/null

# Extract and install
info "Installing to ${INSTALL_DIR}/${BIN_NAME} ..."
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"
install -m 755 "${TMP}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}" \
  || sudo install -m 755 "${TMP}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

info "Done. Run: wazuh-cli"
