#!/bin/sh
# Assembles the static site served at securock.sh.
set -eu
cd "$(dirname "$0")"
rm -rf dist
mkdir dist
cp ../scripts/install.sh dist/install
cp ../scripts/install.sh dist/install.sh
cp _headers _redirects dist/
