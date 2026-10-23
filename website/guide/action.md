---
title: GitHub Action
description: Pin Securock in GitHub Actions by commit SHA, configure scan/diff/verify commands, policy profiles, offline mode, and PR comments.
---

# GitHub Action

Run Securock in CI so pull requests fail on current policy violations and
on trust drift against `securock.lock`.

## Security-first pin

Pin the action to a full commit SHA. That is the only immutable way to
consume a GitHub Action.

```yaml
permissions:
  contents: read
  attestations: read
  pull-requests: write

jobs:
  securock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: securock/securock@COMMIT_SHA
        with:
          command: all
          version: v0.2.1
```

Replace `COMMIT_SHA` with a full commit hash. `@main` tracks a moving
branch and is not the security-first default.

## Inputs

| Input             | Default                | Description                                                                   |
| ----------------- | ---------------------- | ----------------------------------------------------------------------------- |
| `path`            | `.`                    | Project directory to scan                                                     |
| `command`         | `all`                  | `all`, `scan`, `diff`, `verify`, `audit`, `sast`, or `both`                   |
| `policy`          | _(empty)_              | Path to a policy file (`--policy`; exclusive with `profile`)                  |
| `profile`         | _(empty)_              | Built-in profile `default` or `strict` (`--profile`)                          |
| `offline`         | `false`                | Pass `--offline` to the CLI                                                   |
| `reachability`    | `false`                | Pass `--reachability` ([Usage](/guide/usage#reachability))                    |
| `min-release-age` | _(empty)_              | `audit` only: report releases newer than this, such as `7d`                   |
| `sarif`           | `false`                | Upload an audit report to code scanning (needs `security-events: write`)      |
| `sbom`            | `false`                | Write a CycloneDX SBOM and return its path in the `sbom-file` output          |
| `comment`         | `true`                 | Comment a trust report on pull requests                                       |
| `token`           | Actions `github.token` | Token for PR comments and attested release downloads                          |
| `version`         | _(empty)_              | Release tag to install; empty uses a `v*` action ref, else builds from source |

### Code scanning, SBOM, and the cooldown

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
  - id: securock
    uses: securock/securock@COMMIT_SHA
    with:
      command: audit
      reachability: "true"
      min-release-age: 7d
      sarif: "true"
      sbom: "true"
  - uses: actions/upload-artifact@COMMIT_SHA
    with:
      name: sbom
      path: ${{ steps.securock.outputs.sbom-file }}
```

- `command: audit` fails the job on findings at or above `high`, like `securock audit`.
- `command: sast` runs `securock sast` on the project's own source and fails the job on
  findings at or above `high`.
- `sarif: "true"` runs `securock audit --format sarif` (`securock sast --format sarif` when
  `command` is `sast`) from the repository root, so locations match the repository, and
  uploads it to code scanning. The upload never fails the job on its
  own. The report is also returned in the `sarif-file` output.
- `sbom: "true"` runs `securock sbom export`, so `securock.lock` must exist.
- `min-release-age` and `command: audit` are the only way to pass the audit-only flag; other
  commands ignore it.

### `command` modes

| Value                      | Runs                       |
| -------------------------- | -------------------------- |
| `all` (default)            | `scan` + `diff` + `verify` |
| `both`                     | `diff` + `verify` only     |
| `scan` / `diff` / `verify` | That single command        |
| `audit`                    | `securock audit` only      |

Default `all` fails CI on **current** policy violations (`scan`) and on
**trust drift** (`verify`). Use `both` when you only want drift checks
(for example offline fixtures that leave evidence `unknown`).

`policy` and `profile` are mutually exclusive. `offline: true` skips
remote lookups the same way as the CLI.

## Release binary vs source build

After a tagged release exists, set `version` to that tag so the action
downloads the attested binary instead of building from source. A `v*`
action ref does the same. Local checkouts such as `uses: ./` still
build from the action source.

## Permissions and comments

- `contents: read` — check out the repository
- `attestations: read` — download attested release artifacts
- `pull-requests: write` — post the trust report as a PR comment when
  `comment: true`

The action always writes the trust report to `$GITHUB_STEP_SUMMARY`,
even when a pull request comment cannot be posted. Fork PRs often have
a read-only `GITHUB_TOKEN`, so the step summary is the reliable place
to read the report.

## Example: strict profile

```yaml
- uses: securock/securock@COMMIT_SHA
  with:
    command: all
    profile: strict
    version: v0.2.1
```

Prefer `strict` on npm-heavy trees today. Other ecosystems often leave
provenance and signature as `unknown`. See [Policy](/guide/policy).

## Example: custom policy, offline drift check

```yaml
- uses: securock/securock@COMMIT_SHA
  with:
    command: both
    policy: .securock/policy.yaml
    offline: true
    version: v0.2.1
```

## Next steps

- [Usage](/guide/usage) — CLI flags mirrored by these inputs
- [Policy](/guide/policy) — writing `policy.yaml`
- [Threat model](/reference/threat-model) — what CI drift catches
