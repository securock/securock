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

| Input     | Default                | Description                                                                   |
| --------- | ---------------------- | ----------------------------------------------------------------------------- |
| `path`    | `.`                    | Project directory to scan                                                     |
| `command` | `all`                  | `all`, `scan`, `diff`, `verify`, or `both`                                    |
| `policy`  | _(empty)_              | Path to a policy file (`--policy`; exclusive with `profile`)                  |
| `profile` | _(empty)_              | Built-in profile `default` or `strict` (`--profile`)                          |
| `offline` | `false`                | Pass `--offline` to the CLI                                                   |
| `comment` | `true`                 | Comment a trust report on pull requests                                       |
| `token`   | Actions `github.token` | Token for PR comments and attested release downloads                          |
| `version` | _(empty)_              | Release tag to install; empty uses a `v*` action ref, else builds from source |

### `command` modes

| Value                      | Runs                       |
| -------------------------- | -------------------------- |
| `all` (default)            | `scan` + `diff` + `verify` |
| `both`                     | `diff` + `verify` only     |
| `scan` / `diff` / `verify` | That single command        |

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
