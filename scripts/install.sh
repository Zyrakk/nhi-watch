#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-latest}"
REPO="Zyrakk/nhi-watch"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi

FILENAME="nhi-watch_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

echo "Downloading nhi-watch ${VERSION} for ${OS}/${ARCH}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -sL "$URL" -o "${TMPDIR}/${FILENAME}"
curl -sL "$CHECKSUM_URL" -o "${TMPDIR}/checksums.txt"

echo "Verifying SHA256 checksum..."
EXPECTED=$(grep "${FILENAME}" "${TMPDIR}/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "WARNING: checksum not found for ${FILENAME}, skipping verification" >&2
else
  ACTUAL=$(sha256sum "${TMPDIR}/${FILENAME}" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: SHA256 checksum mismatch!" >&2
    echo "  Expected: $EXPECTED" >&2
    echo "  Actual:   $ACTUAL" >&2
    exit 1
  fi
  echo "Checksum verified."
fi

tar -xzf "${TMPDIR}/${FILENAME}" -C "$TMPDIR"

echo "Installing to ${INSTALL_DIR}/nhi-watch..."
install -m 0755 "${TMPDIR}/nhi-watch" "${INSTALL_DIR}/nhi-watch"

echo "nhi-watch ${VERSION} installed successfully."
nhi-watch version 2>/dev/null || true
