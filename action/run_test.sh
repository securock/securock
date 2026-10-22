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
  audit)
    # A SARIF run writes its report to --output, like the real CLI.
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "--output" ]; then
        echo '{"version":"2.1.0"}' >"$arg"
      fi
      prev="$arg"
    done
    if [ "${FAIL_AUDIT:-0}" = 1 ]; then
      echo "audit failed" >&2
      exit 1
    fi
    echo "audit ok"
    ;;
  sbom)
    if [ "${FAIL_SBOM:-0}" = 1 ]; then
      echo "sbom failed" >&2
      exit 1
    fi
    echo '{"bomFormat":"CycloneDX"}'
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

# reachability is forwarded to every command.
run_case reach env COMMAND=scan REACHABILITY=true \
  bash "$root/action/run.sh"
assert_contains "$tmp/reach/calls" "args:scan --reachability"
run_case reach_off env COMMAND=scan REACHABILITY=false \
  bash "$root/action/run.sh"
assert_contains "$tmp/reach_off/calls" "args:scan"
assert_not_contains "$tmp/reach_off/calls" "--reachability"

# audit is its own command, and only audit gets --min-release-age.
run_case audit env COMMAND=audit MIN_RELEASE_AGE=7d REACHABILITY=true \
  bash "$root/action/run.sh"
assert_contains "$tmp/audit/calls" "args:audit --min-release-age 7d --reachability"
assert_contains "$tmp/audit/github_output" "failed=false"
run_case audit_plain env COMMAND=audit \
  bash "$root/action/run.sh"
assert_contains "$tmp/audit_plain/calls" "args:audit"
assert_not_contains "$tmp/audit_plain/calls" "--min-release-age"
run_case audit_fail env COMMAND=audit FAIL_AUDIT=1 \
  bash "$root/action/run.sh"
assert_contains "$tmp/audit_fail/github_output" "failed=true"
run_case age_not_forwarded env COMMAND=scan MIN_RELEASE_AGE=7d \
  bash "$root/action/run.sh"
assert_not_contains "$tmp/age_not_forwarded/calls" "--min-release-age"

# sarif: an audit report is written for code scanning without failing the job on its own.
run_case sarif env COMMAND=scan SARIF_FILE="$tmp/sarif/out.sarif" \
  bash "$root/action/run.sh"
assert_contains "$tmp/sarif/calls" "args:audit . --format sarif --output $tmp/sarif/out.sarif --no-fail"
assert_contains "$tmp/sarif/github_output" "sarif-file=$tmp/sarif/out.sarif"
assert_contains "$tmp/sarif/github_output" "failed=false"
test -s "$tmp/sarif/out.sarif"
# The SARIF run sees the same flags and is made from the directory the job started in.
mkdir -p "$tmp/sarif_dir/project"
run_case sarif_dir env COMMAND=scan WORKDIR=project REACHABILITY=true MIN_RELEASE_AGE=3d \
  SARIF_FILE="$tmp/sarif_dir/out.sarif" bash -c 'cd "$1" && shift && bash "$@"' _ "$tmp/sarif_dir" "$root/action/run.sh"
assert_contains "$tmp/sarif_dir/calls" "args:audit project --format sarif --output $tmp/sarif_dir/out.sarif --no-fail --reachability --min-release-age 3d"
run_case sarif_off env COMMAND=scan \
  bash "$root/action/run.sh"
assert_not_contains "$tmp/sarif_off/calls" "--format sarif"
assert_not_contains "$tmp/sarif_off/github_output" "sarif-file"
run_case sarif_fail env COMMAND=scan SARIF_FILE="$tmp/sarif_fail/out.sarif" FAIL_AUDIT=1 \
  bash "$root/action/run.sh"
assert_contains "$tmp/sarif_fail/github_output" "failed=true"
assert_not_contains "$tmp/sarif_fail/github_output" "sarif-file"

# sbom: the lockfile is exported and its path returned.
run_case sbom env COMMAND=scan SBOM_FILE="$tmp/sbom/bom.json" \
  bash "$root/action/run.sh"
assert_contains "$tmp/sbom/calls" "args:sbom export"
assert_contains "$tmp/sbom/github_output" "sbom-file=$tmp/sbom/bom.json"
assert_contains "$tmp/sbom/bom.json" "CycloneDX"
assert_contains "$tmp/sbom/github_output" "failed=false"
run_case sbom_fail env COMMAND=scan SBOM_FILE="$tmp/sbom_fail/bom.json" FAIL_SBOM=1 \
  bash "$root/action/run.sh"
assert_contains "$tmp/sbom_fail/github_output" "failed=true"
assert_not_contains "$tmp/sbom_fail/github_output" "sbom-file"

echo "ok"
