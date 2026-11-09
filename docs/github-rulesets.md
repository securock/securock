# GitHub rulesets

These settings should be applied on `securock/securock` so `main` cannot
receive unsigned or unreviewed changes. GitHub does not apply rulesets
from the repository automatically; create them in repository settings or
via the API. Keep `.github/rulesets/*.json` in sync with the live
configuration — `scripts/check-rulesets.sh` fails CI when they drift.

## Organization

Enable **Require actions to be pinned to a full-length commit SHA**.

## Protect main: PR review and required checks

- Target: default branch
- Block force pushes
- Block deletions
- Require a pull request before merging
- Require code owner review (`CODEOWNERS`)
- Require approval of the most recent push
- Require conversation resolution
- Dismiss stale reviews on push
- Require status checks:
  - `test`
  - `govulncheck`
  - `analyze (go)` and `analyze (actions)` (CodeQL)
  - `example (examples/npm)`
  - `dependency-review`
  - `release-snapshot`
- The names are those the jobs report, matrix value included: a job in a matrix reports
  as `job (value)`, and a required check that no job reports waits forever
- CI also runs `rulesets` (as-code vs live drift) but it is not a
  required check, so fork PRs are not blocked by missing admin token
  scopes
- One bypass actor: the repository owner (`minagishl`, user ID 114616680), always. Nobody else
  can skip the review or the required checks

Example payload: `.github/rulesets/main.json`.

## Protect release tags: no delete or rewrite

- Target: tags matching `v*`
- Block tag deletions
- Block force-pushes that rewrite a release tag
- No permanent bypass actors

Tag creation is intentionally unrestricted in the ruleset today so
maintainers can cut releases; `release.yml` still requires the tag to
point at current `main` HEAD. Prefer adding a release-bot-only
`creation` restriction once that bot exists.

Example payload: `.github/rulesets/tags.json`.

## Require signed commits on all branches

- Target: all branches (`~ALL`)
- Require signed commits (`required_signatures`): a push is rejected when any
  new commit is unsigned or its signature is not verified by GitHub
- No bypass actors, so nobody is exempt

The rule applies to commits pushed after it was created. Commits already on a
branch are not rewritten; signing them would change their hashes and needs a
force push, which the `main` ruleset blocks.

Example payload: `.github/rulesets/signed-commits.json`.

## Immutable releases

Enable **Immutable releases** on `securock/securock` (repository Settings →
Releases, or `PUT /repos/securock/securock/immutable-releases`).

Once enabled, published releases lock their Git tag and assets. The Release
workflow already creates a draft, attaches artifacts and attestations, then
publishes — the pattern GitHub recommends for immutable releases.

Immutability applies to releases published after the setting is enabled.
Verify with:

```bash
gh api repos/securock/securock/immutable-releases --jq .enabled
```

## Drift check

```bash
./scripts/check-rulesets.sh
```

CI runs the same check. The Rulesets API needs Administration: Read,
so set repository secret `RULESETS_TOKEN` to a fine-grained PAT with
that permission. Without it, the job falls back to `GITHUB_TOKEN` and
may fail with 403.
