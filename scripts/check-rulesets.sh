#!/bin/sh
# Compare .github/rulesets/*.json to the live GitHub repository rulesets.
# Fails when names, enforcement, PR parameters, required checks, or
# tag rules drift. Requires gh authenticated with repo admin read access.
set -eu

REPO="${GITHUB_REPOSITORY:-securock/securock}"
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
RULESETS_DIR="$ROOT/.github/rulesets"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh api "repos/$REPO/rulesets" --paginate >"$tmp/index.json"

python3 - "$RULESETS_DIR" "$tmp" "$REPO" <<'PY'
import json, os, sys, subprocess, urllib.error

rulesets_dir, tmp, repo = sys.argv[1:4]

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def normalize_desired(doc):
    rules = []
    for rule in doc.get("rules", []):
        entry = {"type": rule["type"]}
        params = rule.get("parameters")
        if params is not None:
            # Drop fields GitHub may omit or expand differently.
            cleaned = dict(params)
            if "required_status_checks" in cleaned:
                checks = sorted(
                    (c.get("context") for c in cleaned["required_status_checks"] if c.get("context")),
                    key=str,
                )
                cleaned["required_status_checks"] = [{"context": c} for c in checks]
            entry["parameters"] = cleaned
        rules.append(entry)
    rules.sort(key=lambda r: r["type"])
    return {
        "name": doc["name"],
        "target": doc["target"],
        "enforcement": doc["enforcement"],
        "bypass_actors": doc.get("bypass_actors", []),
        "conditions": doc.get("conditions", {}),
        "rules": rules,
    }

def normalize_live(doc):
    rules = []
    for rule in doc.get("rules", []):
        entry = {"type": rule["type"]}
        params = rule.get("parameters")
        if params is not None:
            cleaned = {}
            # Compare only the PR knobs we manage in as-code.
            if rule["type"] == "pull_request":
                for key in (
                    "required_approving_review_count",
                    "dismiss_stale_reviews_on_push",
                    "require_code_owner_review",
                    "require_last_push_approval",
                    "required_review_thread_resolution",
                ):
                    if key in params:
                        cleaned[key] = params[key]
            elif rule["type"] == "required_status_checks":
                cleaned["strict_required_status_checks_policy"] = params.get(
                    "strict_required_status_checks_policy"
                )
                checks = sorted(
                    (
                        c.get("context")
                        for c in params.get("required_status_checks", [])
                        if c.get("context")
                    ),
                    key=str,
                )
                cleaned["required_status_checks"] = [{"context": c} for c in checks]
            else:
                cleaned = params
            entry["parameters"] = cleaned
        rules.append(entry)
    rules.sort(key=lambda r: r["type"])
    bypass = []
    for actor in doc.get("bypass_actors") or []:
        bypass.append(
            {
                "actor_id": actor.get("actor_id"),
                "actor_type": actor.get("actor_type"),
                "bypass_mode": actor.get("bypass_mode"),
            }
        )
    bypass.sort(key=lambda a: (str(a.get("actor_type")), str(a.get("actor_id"))))
    return {
        "name": doc["name"],
        "target": doc["target"],
        "enforcement": doc["enforcement"],
        "bypass_actors": bypass,
        "conditions": doc.get("conditions", {}),
        "rules": rules,
    }

index = load(os.path.join(tmp, "index.json"))
live_by_name = {item["name"]: item for item in index}

desired_files = sorted(
    f for f in os.listdir(rulesets_dir) if f.endswith(".json")
)
if not desired_files:
    print("no ruleset files found", file=sys.stderr)
    sys.exit(1)

failed = False
for name in desired_files:
    desired = normalize_desired(load(os.path.join(rulesets_dir, name)))
    live_meta = live_by_name.get(desired["name"])
    if live_meta is None:
        print(f"FAIL: live ruleset missing for {desired['name']}", file=sys.stderr)
        failed = True
        continue
    ruleset_id = live_meta["id"]
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/rulesets/{ruleset_id}"],
        check=True,
        capture_output=True,
        text=True,
    )
    live = normalize_live(json.loads(proc.stdout))
    # Desired empty bypass_actors means no bypass; live must also be empty.
    if desired["bypass_actors"] == []:
        live["bypass_actors"] = live["bypass_actors"]  # already normalized
    if desired != live:
        print(f"FAIL: drift in ruleset {desired['name']}", file=sys.stderr)
        print("desired:", json.dumps(desired, indent=2, sort_keys=True), file=sys.stderr)
        print("live:", json.dumps(live, indent=2, sort_keys=True), file=sys.stderr)
        failed = True
    else:
        print(f"ok: {desired['name']}")

if failed:
    sys.exit(1)
PY
