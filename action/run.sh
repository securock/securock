#!/usr/bin/env bash
set -euo pipefail

command="${COMMAND:-all}"
workdir="${WORKDIR:-.}"
offline="${OFFLINE:-false}"
policy="${POLICY:-}"
profile="${PROFILE:-}"
report="${SECUROCK_REPORT:?SECUROCK_REPORT is required}"

cd "$workdir"

if [ -n "$policy" ] && [ -n "$profile" ]; then
  echo "policy and profile are mutually exclusive" | tee "$report" >&2
  echo "failed=true" >>"$GITHUB_OUTPUT"
  exit 1
fi

flags=()
if [ "$offline" = "true" ]; then
  flags+=(--offline)
fi
if [ -n "$policy" ]; then
  flags+=(--policy "$policy")
fi
if [ -n "$profile" ]; then
  flags+=(--profile "$profile")
fi

: >"$report"
failed=false

run_cmd() {
  local name="$1"
  shift
  {
    echo "$name"
    echo
    if [ "${#flags[@]}" -eq 0 ]; then
      "$@"
    else
      "$@" "${flags[@]}"
    fi
  } >>"$report" 2>&1 && return 0
  failed=true
  return 0
}

case "$command" in
  scan)
    run_cmd "securock scan" securock scan
    ;;
  diff)
    run_cmd "securock diff" securock diff
    ;;
  verify)
    run_cmd "securock verify" securock verify
    ;;
  both)
    # Drift-only path for callers that intentionally skip current-state
    # policy checks (for example offline fixtures with unknown evidence).
    run_cmd "securock diff" securock diff
    echo >>"$report"
    run_cmd "securock verify" securock verify
    ;;
  all)
    run_cmd "securock scan" securock scan
    echo >>"$report"
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

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Securock Trust Report"
    echo
    echo '```'
    cat "$report"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failed" = true ]; then
  echo "failed=true" >>"$GITHUB_OUTPUT"
else
  echo "failed=false" >>"$GITHUB_OUTPUT"
fi
