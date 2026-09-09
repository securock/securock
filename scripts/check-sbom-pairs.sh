#!/bin/sh
set -eu

json=0
dist=dist

while [ $# -gt 0 ]; do
  case "$1" in
    --json)
      json=1
      shift
      ;;
    *)
      dist=$1
      shift
      ;;
  esac
done

count=0
first=1
if [ "$json" -eq 1 ]; then
  printf '['
fi

for archive in "$dist"/*.tar.gz "$dist"/*.zip; do
  [ -f "$archive" ] || continue
  sbom="${archive}.sbom.json"
  if [ ! -f "$sbom" ]; then
    echo "missing SBOM for ${archive}: expected ${sbom}" >&2
    exit 1
  fi
  echo "ok ${archive} -> ${sbom}" >&2
  if [ "$json" -eq 1 ]; then
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '{"archive":"%s","sbom":"%s"}' "$archive" "$sbom"
  fi
  count=$((count + 1))
done

if [ "$json" -eq 1 ]; then
  printf ']'
fi

if [ "$count" -eq 0 ]; then
  echo "no release archives found in ${dist}" >&2
  exit 1
fi

echo "paired ${count} archives with SBOMs" >&2
