# GitHub rulesets

These settings should be applied on `securock/securock` so `main` cannot
receive unsigned or unreviewed changes. GitHub does not apply rulesets
from the repository automatically; create them in repository settings or
via the API. Keep `.github/rulesets/*.json` in sync with the live
configuration — `scripts/check-rulesets.sh` fails CI when they drift.

## Organization

Enable **Require actions to be pinned to a full-length commit SHA**.

## `main` ruleset

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
  - `analyze` (CodeQL)
  - `npm-example`
  - `dependency-review`
  - `release-snapshot`
- CI also runs `rulesets` (as-code vs live drift) but it is not a
  required check, so fork PRs are not blocked by missing admin token
  scopes
- No permanent bypass actors (empty `bypass_actors`)

Example payload: `.github/rulesets/main.json`.

## `v*` tag ruleset

- Target: tags matching `v*`
- Block tag deletions
- Block force-pushes that rewrite a release tag
- No permanent bypass actors

Tag creation is intentionally unrestricted in the ruleset today so
maintainers can cut releases; `release.yml` still requires the tag to
point at current `main` HEAD. Prefer adding a release-bot-only
`creation` restriction once that bot exists.

Example payload: `.github/rulesets/tags.json`.

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
