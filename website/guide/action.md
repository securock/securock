# GitHub Action

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
      - uses: securock/securock@<commit-sha>
        with:
          command: all
          version: v0.2.1
```

`command` is `all` (default: `scan` + `diff` + `verify`), `scan`,
`diff`, `verify`, or `both` (`diff` + `verify` only). Default `all`
fails CI on current policy violations and on trust drift. Use `both`
when you only want drift checks (for example offline fixtures that
leave evidence `unknown`).

`policy` passes `--policy` and `profile` passes `--profile`. They are
mutually exclusive. `offline: true` passes `--offline` to the CLI.

After a tagged release exists, set `version` to that tag so the action
downloads the attested binary instead of building from source. A `v*`
action ref does the same. Local checkouts such as `uses: ./` still
build from the action source.

`@main` tracks a moving branch and is not the security-first default.

The action writes the trust report to `$GITHUB_STEP_SUMMARY` even when a
pull request comment cannot be posted (fork PRs often have a read-only
`GITHUB_TOKEN`).
