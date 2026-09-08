#!/bin/sh
set -eu

REPO="${REPO:-securock/securock}"
BINARY="${BINARY:-securock}"
INSTALL_DIR="${INSTALL_DIR:-}"
SKIP_ATTESTATION="${SKIP_ATTESTATION:-}"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Darwin) os=Darwin ;;
  Linux) os=Linux ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

archive="${BINARY}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/latest/download"
archive_url="${base}/${archive}"
checksums_url="${base}/checksums.txt"

if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "$INSTALL_DIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

download() {
  url=$1
  dest=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
}

download "$checksums_url" "${tmp}/checksums.txt"
download "$archive_url" "${tmp}/${archive}"

expected=$(awk -v name="$archive" '$2 == name { print $1; exit }' "${tmp}/checksums.txt")
if [ -z "$expected" ]; then
  echo "no checksum for ${archive}" >&2
  exit 1
fi

got=$(sha256 "${tmp}/${archive}")
if [ "$got" != "$expected" ]; then
  echo "checksum mismatch for ${archive}" >&2
  echo "expected ${expected}" >&2
  echo "got      ${got}" >&2
  exit 1
fi

if [ -z "$SKIP_ATTESTATION" ] && command -v gh >/dev/null 2>&1; then
  gh attestation verify "${tmp}/${archive}" --repo "$REPO"
fi

tar -xzf "${tmp}/${archive}" -C "$tmp"
install -m 0755 "${tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo "installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
