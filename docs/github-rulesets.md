# GitHub rulesets

These settings should be applied on `securock/securock` so `main` cannot
receive unsigned or unreviewed changes. GitHub does not apply rulesets
from the repository automatically; create them in repository settings or
via the API.

## Organization

Enable **Require actions to be pinned to a full-length commit SHA**.

## `main` ruleset

- Target: default branch
- Block force pushes
- Block deletions
- Require a pull request before merging
- Require status checks:
  - `test`
  - `govulncheck`
  - `analyze` (CodeQL)
- Do not allow bypass except for repository admins during an incident

Example payload: `.github/rulesets/main.json`.
