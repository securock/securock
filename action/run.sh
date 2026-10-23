#!/usr/bin/env bash
set -euo pipefail

command="${COMMAND:-all}"
workdir="${WORKDIR:-.}"
offline="${OFFLINE:-false}"
policy="${POLICY:-}"
profile="${PROFILE:-}"
reachability="${REACHABILITY:-false}"
min_release_age="${MIN_RELEASE_AGE:-}"
sarif_file="${SARIF_FILE:-}"
sbom_file="${SBOM_FILE:-}"
report="${SECUROCK_REPORT:?SECUROCK_REPORT is required}"

origin="$PWD"
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
if [ "$reachability" = "true" ]; then
  flags+=(--reachability)
fi

# Flags only audit understands.
audit_flags=()
if [ -n "$min_release_age" ]; then
  audit_flags+=(--min-release-age "$min_release_age")
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
  audit)
    run_cmd "securock audit" securock audit ${audit_flags[@]+"${audit_flags[@]}"}
    ;;
  sast)
    run_cmd "securock sast" securock sast
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

# Optional artifacts. They are written from the directory the job started in, so paths in
# the SARIF report are relative to the repository root, which code scanning needs.
if [ -n "$sarif_file" ]; then
  # The code scanning report matches the command: source findings for sast, dependency
  # findings for everything else.
  sarif_cmd=audit
  sarif_flags=(${audit_flags[@]+"${audit_flags[@]}"})
  if [ "$command" = "sast" ]; then
    sarif_cmd=sast
    sarif_flags=()
  fi
  # --no-fail: the report is for code scanning; the step above decides pass or fail.
  if (cd "$origin" && securock "$sarif_cmd" "$workdir" --format sarif --output "$sarif_file" --no-fail \
      ${flags[@]+"${flags[@]}"} ${sarif_flags[@]+"${sarif_flags[@]}"}) >>"$report" 2>&1; then
    echo "sarif-file=$sarif_file" >>"$GITHUB_OUTPUT"
  else
    echo "securock $sarif_cmd --format sarif failed" >>"$report"
    failed=true
  fi
fi
if [ -n "$sbom_file" ]; then
  if securock sbom export ${flags[@]+"${flags[@]}"} >"$sbom_file" 2>>"$report"; then
    echo "sbom-file=$sbom_file" >>"$GITHUB_OUTPUT"
  else
    echo "securock sbom export failed" >>"$report"
    failed=true
  fi
fi

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
