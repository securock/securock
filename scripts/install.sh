#!/bin/sh
set -eu

REPO="${REPO:-securock/securock}"
BINARY="${BINARY:-securock}"
INSTALL_DIR="${INSTALL_DIR:-}"

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
url="https://github.com/${REPO}/releases/latest/download/${archive}"

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

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "${tmp}/${archive}"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${tmp}/${archive}" "$url"
else
  echo "curl or wget is required" >&2
  exit 1
fi

tar -xzf "${tmp}/${archive}" -C "$tmp"
install -m 0755 "${tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo "installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
