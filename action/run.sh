#!/usr/bin/env bash
set -euo pipefail

command="${COMMAND:-both}"
workdir="${WORKDIR:-.}"
offline="${OFFLINE:-false}"
report="${SECUROCK_REPORT:?SECUROCK_REPORT is required}"

cd "$workdir"

flags=()
if [ "$offline" = "true" ]; then
  flags+=(--offline)
fi

: >"$report"
failed=false

run_cmd() {
  local name="$1"
  shift
  {
    echo "$name"
    echo
    "$@" "${flags[@]}"
  } >>"$report" 2>&1 && return 0
  failed=true
  return 0
}

case "$command" in
  diff)
    run_cmd "securock diff" securock diff
    ;;
  verify)
    run_cmd "securock verify" securock verify
    ;;
  both)
    run_cmd "securock diff" securock diff
    echo >>"$report"
    run_cmd "securock verify" securock verify
    ;;
  *)
    echo "unknown command: $command" | tee "$report" >&2
    echo "failed=true" >>"$GITHUB_OUTPUT"
    exit 1
    ;;
esac

cat "$report"

if [ "$failed" = true ]; then
  echo "failed=true" >>"$GITHUB_OUTPUT"
else
  echo "failed=false" >>"$GITHUB_OUTPUT"
fi
