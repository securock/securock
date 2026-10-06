#!/usr/bin/env bash
# Tests for action/run.sh. Invoked as: bash action/run_test.sh
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bin="$tmp/bin"
mkdir -p "$bin"
PATH="$bin:$PATH"

cat >"$bin/securock" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "args:$*" >>"${CALL_LOG:?}"
case "${1:-}" in
  scan)
    if [ "${FAIL_SCAN:-0}" = 1 ]; then
      echo "scan failed" >&2
      exit 1
    fi
    echo "scan ok"
    ;;
  diff)
    if [ "${FAIL_DIFF:-0}" = 1 ]; then
      echo "diff failed" >&2
      exit 1
    fi
    echo "diff ok"
    ;;
  verify)
    if [ "${FAIL_VERIFY:-0}" = 1 ]; then
      echo "verify failed" >&2
      exit 1
    fi
    echo "verify ok"
    ;;
  *)
    echo "unexpected: $*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$bin/securock"

run_case() {
  local name="$1"
  shift
  local out="$tmp/$name"
  mkdir -p "$out"
  : >"$out/calls"
  : >"$out/github_output"
  CALL_LOG="$out/calls" SECUROCK_REPORT="$out/report" GITHUB_OUTPUT="$out/github_output" \
    "$@" >"$out/stdout" 2>"$out/stderr" || true
}

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "missing in $file: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$file"; then
    echo "unexpected in $file: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

# Default command runs scan, then diff, then verify.
run_case default env -u COMMAND FAIL_SCAN=0 FAIL_DIFF=0 FAIL_VERIFY=0 \
  bash "$root/action/run.sh"
assert_contains "$tmp/default/calls" "args:scan"
assert_contains "$tmp/default/calls" "args:diff"
assert_contains "$tmp/default/calls" "args:verify"
assert_contains "$tmp/default/github_output" "failed=false"

# both skips scan.
run_case both env COMMAND=both FAIL_SCAN=1 \
  bash "$root/action/run.sh"
assert_not_contains "$tmp/both/calls" "args:scan"
assert_contains "$tmp/both/calls" "args:diff"
assert_contains "$tmp/both/calls" "args:verify"
assert_contains "$tmp/both/github_output" "failed=false"

# scan failure marks the step failed without aborting later commands in all.
run_case all_fail env COMMAND=all FAIL_SCAN=1 \
  bash "$root/action/run.sh"
assert_contains "$tmp/all_fail/calls" "args:scan"
assert_contains "$tmp/all_fail/calls" "args:diff"
assert_contains "$tmp/all_fail/calls" "args:verify"
assert_contains "$tmp/all_fail/github_output" "failed=true"

# profile flag is forwarded.
run_case profile env COMMAND=scan PROFILE=strict \
  bash "$root/action/run.sh"
assert_contains "$tmp/profile/calls" "args:scan --profile strict"
assert_contains "$tmp/profile/github_output" "failed=false"

# policy flag is forwarded.
run_case policy env COMMAND=scan POLICY=policy.yaml \
  bash "$root/action/run.sh"
assert_contains "$tmp/policy/calls" "args:scan --policy policy.yaml"
assert_contains "$tmp/policy/github_output" "failed=false"

# policy and profile are mutually exclusive.
run_case exclusive env COMMAND=scan POLICY=policy.yaml PROFILE=strict \
  bash "$root/action/run.sh"
assert_contains "$tmp/exclusive/stderr" "mutually exclusive"
assert_contains "$tmp/exclusive/github_output" "failed=true"

echo "ok"
