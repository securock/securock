---
title: Usage
description: Securock CLI commands, flags, and exit codes — the lock, diff, verify, and update loop over securock.lock, plus audit, explain, doctor, JSON and SARIF output.
---

# Usage

Securock reads language lockfiles, applies a policy, and either writes
or compares against `securock.lock`.

```sh
securock scan [path]
securock init [path]
securock lock [path]
securock diff [path]
securock update [path]
securock verify [path]
securock explain PACKAGE [path]
securock graph [path]
securock audit [path]
securock sast [path]
securock chain [path]
securock doctor [path]
securock sbom export [path]
securock sbom verify SBOM [path]
securock accept FINDING-ID [path]
securock vex export [path]
securock version
```

`scan` is the default when no command is given.

> `trusted` means the artifact passed the **active policy**, not that it
> is cryptographically verified. The CLI prints this as
> `trusted (under active policy)`.

## Commands

| Command   | What it does                                                 | More                                                        |
| --------- | ------------------------------------------------------------ | ----------------------------------------------------------- |
| `scan`    | Inspect the current tree under the active policy (default)   | [scan / verify](#scan-vs-verify)                            |
| `init`    | Detect lockfiles and write the first `securock.lock`         | [init](#init)                                               |
| `lock`    | Write a deterministic `securock.lock`                        | [Lockfile](/reference/lockfile)                             |
| `diff`    | Show trust drift versus the lockfile                         | [scan / verify](#scan-vs-verify)                            |
| `update`  | Review trust changes, then refresh the lockfile              | [update](#update)                                           |
| `verify`  | Fail on trust-relevant drift versus the lockfile             | [scan / verify](#scan-vs-verify)                            |
| `explain` | Print a trust checklist for one package                      | [explain](#explain)                                         |
| `graph`   | Draw the dependency graph colored by trust status            | [graph](#graph)                                             |
| `audit`   | Report dependency findings ranked by severity                | [audit](#audit)                                             |
| `sast`    | Find vulnerabilities in your own source code                 | [Source code analysis](/guide/sast)                         |
| `chain`   | Correlate source findings into attack chains                 | [Source code analysis](/guide/sast)                         |
| `import`  | Bring another tool's SARIF results under securock's policy   | [import](#import)                                           |
| `doctor`  | Check the project setup for security problems                | [doctor](#doctor)                                           |
| `sbom`    | Export the lockfile as an SBOM, or verify an SBOM against it | [Triage and exports](/guide/reports#sbom-export-and-verify) |
| `accept`  | Accept a finding until a date, with a reason                 | [Triage and exports](/guide/reports#accept-findings)        |
| `vex`     | Export accepted vulnerabilities as OpenVEX or CycloneDX VEX  | [Triage and exports](/guide/reports#vex-export)             |
| `version` | Print the build version                                      |                                                             |

## The core commands

### `update`

`update` is the review step after a dependency update. It scans the tree,
prints the same report as `diff`, and records the new state in
`securock.lock` only when you ask.

```sh
securock update              # preview: show what changed, write nothing
securock update --write      # record the new state
```

- Without `--write` the lockfile is never touched and the command exits `0`,
  so it is a preview, not a gate. Use `verify` to fail CI on drift.
- `--write` refuses to record a state that has untrusted or unknown
  artifacts and exits `1` without changing the file. Add `--no-fail` to record
  it anyway, for example for a first offline snapshot.
- When the lockfile already matches the tree, it reports `up to date` and
  leaves the file byte-identical.
- It needs an existing `securock.lock`; run `securock lock` once to create it.
- `--format json` prints the `diff` report (`diff-report` schema) on stdout and
  moves the status lines to stderr. `--format sarif` is not supported.

### `init`

`init` sets a project up: it detects the lockfiles, records the current trust state
in `securock.lock`, prints a summary, and says what to run next. It is the first run of
`lock` plus that summary, so it refuses to overwrite an existing `securock.lock`; use
`lock` to refresh one.

```sh
securock init
securock init --profile strict --write-policy
```

`--write-policy` also writes the profile in use (`default` or `strict`) to
`.securock/policy.yaml`, as a starting point to edit. It never overwrites an existing
file. Pass the file with `--policy` afterwards.

Like `lock`, `init` exits `1` when the snapshot has untrusted or unknown artifacts,
which is normal for a first `--offline` run; the files are written either way. Use
`--no-fail` to exit `0`.

### `scan` vs `verify`

These answer different questions:

- **`scan`** fails on **current** policy violations even when
  `securock.lock` already records them. Use it to keep the tree honest
  under today's policy.
- **`verify`** fails when the tree **drifts** from the accepted lockfile
  (digest, evidence, ownership, capabilities, trust reasons, and so on).
- **`diff`** is the operator view of the same comparison `verify` uses.

The GitHub Action default (`command: all`) runs `scan`, then `diff`,
then `verify`. See
[Trust model](/reference/trust-model) for what each status means, and
[Lockfile](/reference/lockfile) for what counts as drift.

### `explain`

`explain PACKAGE` prints digest, source, provenance, signature, trust
chain, ownership, capabilities, vulnerabilities, and malicious-package
checks for one subject under the active policy.

```sh
securock explain react
securock explain react --format json
securock explain lodash --reachability
```

### `graph`

`graph` draws the dependency graph read from your lockfiles, with the trust
status of every package. The default is a tree; `--format mermaid` and
`--format dot` print a diagram that GitHub, GitLab, and Graphviz render.

```sh
securock graph
securock graph --problems
securock graph --format mermaid >> "$GITHUB_STEP_SUMMARY"
securock graph --format dot | dot -Tsvg > deps.svg
```

`--problems` keeps only the packages that are `untrusted` or `unknown`, and the
packages that lead to them, so it shows why each one is in the project. A package
met a second time in the tree is marked `(*)` and not expanded again.

Edges come from the lockfile and not every resolver records them
([Reachability](/guide/ecosystems#reachability)). When none are recorded, `graph`
lists top-level packages only and says so, rather than drawing a flat graph that
looks like a project with no transitive dependencies. `graph` always collects
scope and edges, as `--reachability` does.

## Findings with `audit`

`audit` turns scan evidence into findings: malicious packages are
`critical`, known vulnerabilities are `high`, and missing digests,
provenance or signatures rank lower. Evidence that was not checked is
reported as `info`, so offline runs always have `info` findings.
It accepts `--fail-on SEVERITY` (`critical`, `high`, `medium`, `low`
or `info`; default `high`) and exits `1` when a finding is at or above
it. `doctor`, `sast` and `chain` use the same flag; `chain` counts
confirmed chains only.

`audit` also takes `--min-release-age 7d`, which reports releases newer
than that as high findings (the default comes from `rules.health.min_release_age`
in the policy, if set); see
[Release cooldown](/guide/evidence#release-cooldown).

### Severity and fixed versions

For every advisory that matches, Securock reads its OSV record and stores the `severity`
(`critical`, `high`, `medium`, or `low`) and the `fixed` versions on the vulnerability in the
lockfile. Severity is the CVSS v3 base score when the advisory has a v3 vector, otherwise the
rating the advisory database attached (GitHub's `moderate` is `medium`). CVSS v2 and v4 vectors
are not computed, so an advisory with only those and no database rating has no severity.
`fixed` is the version that ends the affected range containing your version, so a fix for an
old release branch does not show up for a newer one.

`audit` ranks each known vulnerability by its severity, still high when none is recorded,
and the remediation names the version to upgrade to. Reachability can still lower a
vulnerability to low, never raise it. `explain` and the CycloneDX SBOM (`ratings`) show the
same data. Severity and fixed versions are not trust drift.

### Reachability

A dependency scan finds a vulnerable package whether or not it ends up in what you ship. A
vulnerability in a test runner and one in your web framework look the same in a lockfile.
`--reachability` tells them apart using the dependency graph:

```sh
securock audit --reachability
securock lock --reachability
securock explain lodash --reachability
```

For each package it records how it enters the project (`scope`: `runtime`, `dev`, or `optional`)
and its direct `dependencies`, then marks every known vulnerability:

| `reachable` | Meaning                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------- |
| `yes`       | A runtime package is, or depends on, the vulnerable one. `via` shows the shortest path.     |
| `no`        | The lockfile marks the package development-only and no runtime package depends on it.       |
| `unknown`   | Anything else: optional packages, and lockfiles that record neither scope nor dependencies. |

`audit` lists a `no` as a **low** finding ("development-only dependency") so it no longer fails
`--fail-on high`, and shows the path for a `yes`. Reachability never raises a severity and never
turns `unknown` into `no`: missing information is not evidence of safety.

This is the graph, not the code. It cannot tell whether your code calls the vulnerable function, and
`yes` means "not shown to be development-only", not "exploitable". Which resolvers can supply scope
and edges is in [Ecosystems](/guide/ecosystems#reachability).

Scope and dependencies are only written when `--reachability` is set, and changing them is not
trust drift: `verify` with or without the flag accepts the same lockfile.

### `doctor`

`doctor` checks the setup around securock: the lockfile and policy,
registry config (`.npmrc`, `.yarnrc.yml`, `nuget.config`) for plain
http, disabled TLS and literal credentials, workflow actions that are
not pinned to a commit SHA, and missing repository rulesets. It also
reports expired exceptions, those expiring within 14 days, and
exceptions with no approver. Its findings follow the same
`--fail-on` flow as `audit`.

## Response cache

Registry and OSV responses are cached on disk for one hour, so repeated runs (a
[pre-commit hook](#git-hooks), `--recursive`, a CI retry) do not ask again.

```sh
securock verify --no-cache          # skip the cache for one run
securock verify --cache-ttl 10m     # use responses for 10 minutes instead
securock cache clear                # delete every cached response
```

The cache lives in your user cache directory (`securock/`), readable only by you.
Requests that carry credentials (`Authorization`, `Cookie`) are never cached, and a
response is stored whole or not at all, so a run that starts while another is writing
never reads half of one. Only successful responses are kept. The cache saves time and
does not change what is reported: an entry older than `--cache-ttl` is fetched again.

## Monorepos

A repository with a lockfile per service keeps one `securock.lock` per project, next to
its lockfile. `--recursive` (`-r`) runs `lock`, `scan`, `diff`, `verify`, or `audit` for
every project under the path:

```sh
securock lock --recursive
securock verify --recursive
securock audit -r services/
```

Each project's report follows a `== path ==` heading (`# path` with `--format markdown`).
A project is a directory that holds a lockfile securock reads. Hidden directories and
`node_modules`, `vendor`, `target`, `dist`, `build`, `out`, `venv`, `site-packages`,
`__pycache__`, `testdata`, and `Pods` are not searched, and symbolic links are not
followed.

- Every project runs even after one fails, so one run shows all of them. The exit code is
  the worst result: `2` for an error, else `1` for a trust failure, else `0`.
- Finding no project is an error, not a pass.
- `--format json`, `sarif`, and `junit` are refused, since several reports in one stream
  are not one valid document. Run once per project for those.
- A relative `--lock` path is resolved inside each project.

## Git hooks

Catch drift before it reaches CI. With [pre-commit](https://pre-commit.com), add the
hooks to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/securock/securock
    rev: v0.3.0 # use the latest release tag
    hooks:
      - id: securock-verify
      - id: securock-audit
```

`securock-verify` runs `securock verify` and `securock-audit` runs `securock audit`.
Each runs only when a lockfile, `securock.lock`, or `.securock/exceptions.yaml` is
staged, and checks the whole project. pre-commit builds the CLI from the tagged
release, so Go must be installed. Pass options with `args`, for example
`args: [--policy, policy.yaml]`.

The hooks look packages up online, like the CLI. `args: [--offline]` skips that, but
remote evidence stays `unknown`, so `verify` reports drift against a lockfile that
recorded it. Lock and hook should use the same mode.

With [lefthook](https://lefthook.dev), or any runner that calls commands:

```yaml
pre-commit:
  commands:
    securock:
      glob: "{securock.lock,*.lock,package-lock.json,pnpm-lock.yaml,go.sum}"
      run: securock verify
```

## Shared flags

| Flag             | Meaning                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `--network`      | `public-only` (default), `offline`, or `allow-all`                                          |
| `--offline`      | Skip remote lookups; remote evidence stays `unknown`                                        |
| `--policy`       | Path to a policy file                                                                       |
| `--profile`      | Built-in policy: `default` or `strict` (not with `--policy`)                                |
| `--lock`         | Path to `securock.lock` (for `lock` / `diff` / `update` / `verify`)                         |
| `--format`       | `text` (default), `json`, `sarif`, `junit`, or `markdown` (`graph`: `mermaid`, `dot`)       |
| `--recursive`    | `lock`, `scan`, `diff`, `verify`, `audit`: run for every project under the path             |
| `--no-cache`     | Do not read or write the on-disk cache of registry and OSV responses                        |
| `--cache-ttl`    | How long a cached response is used, such as `10m` or `24h` (default `1h`)                   |
| `--output`       | Write the report to a file instead of stdout                                                |
| `--exceptions`   | Path to the accepted-findings file (`accept`, `audit`, `sast`, `chain`, `import`, `doctor`) |
| `--reachability` | Record scope and dependencies and mark vulnerabilities reachable, unreachable, or unknown   |
| `--no-fail`      | Always exit `0`                                                                             |

`--offline` records vulnerability, malicious, capability, behavior,
ownership, provenance, signature, and chain evidence as `unknown`.

`--policy` and `--profile` are mutually exclusive. See
[Policy](/guide/policy) for profiles and YAML rules.

`sast` also takes `--import <file.sarif>` to merge another scanner's findings into its report;
see [Source code analysis](/guide/sast#other-scanners-in-the-same-report).

`sast` also takes `--assume-params`; see
[Source code analysis](/guide/sast#taint-tracking). `chain` takes it
too, since it reuses the sast analysis.

### `chain`

`chain` runs the sast analysis and correlates the findings into attack
chains: an entry where attacker-controlled data crosses a boundary, the
injection sinks it reaches, and committed credentials an attacker could
read on the way. A single dataflow finding whose trace proves the whole
path is a `confirmed` chain; findings that share a file form a
`possible` chain unless both are proven inside the same function.
Possible chains are reported but never fail a build — `--fail-on`
counts confirmed chains only.

```sh
securock chain --format sarif --output chains.sarif
```

### `import`

`import` reads SARIF 2.1.0 reports from other scanners (CodeQL, Semgrep,
Trivy, Checkov and the like) and handles them like Securock's own
findings: ranked by severity, accepted through the exceptions file, and
failing the build at `--fail-on`. Pass `-` to read stdin.

```sh
semgrep scan --sarif --output semgrep.sarif
securock import semgrep.sarif codeql.sarif --fail-on high
```

A finding's ID is `sarif:<tool>/<rule>` and its subject is the file it
points at, so an exception looks like this:

```sh
securock accept sarif:semgrep/go.sqli --subject cmd/x.go \
  --reason "input is validated upstream" --expires 2026-12-31
```

Severity comes from the numeric `security-severity` property when present
(9.0 and above is `critical`, 7.0 `high`, 4.0 `medium`), then from the
SARIF level (`error` is `high`, `warning` `medium`, `note` `low`). A result
with neither is `medium`. A suppression inside the SARIF file is not
honored: only the exceptions file accepts a finding. `import` reads
`.securock/exceptions.yaml` from the current directory unless you pass
`--exceptions`.

An absolute file path under the current directory is made relative to it, so a report made
on a CI runner matches exceptions written for `cmd/x.go`. A path outside it is kept as the
tool wrote it.

## Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| `0`  | Success / no trust drift (for `verify`) |
| `1`  | Trust violation                         |
| `2`  | Configuration or operational error      |

## JSON, SARIF, JUnit and Markdown output

```sh
securock scan --format json
securock diff --format json
securock verify --format json
securock explain react --format json
securock audit --format sarif
securock verify --format sarif --output securock.sarif
```

- `scan --format json` emits the lock document shape.
- `diff` and `verify` print a `schema_version: 1` report.
- `explain --format json` emits the matched artifacts.
- `--format sarif` works on `scan`, `diff`, `verify`, `audit`, `sast`,
  `chain`, and `doctor`.
  Results point at `securock.lock` and name the package as a logical
  location. Each result has a stable `partialFingerprints` entry so code
  scanning can track it across runs. `sast` results point at the source
  line and carry a `codeFlows` trace. `chain` results carry the chain's
  stages as the code flow. `--output` writes the file even
  when the command exits `1`, so a failing `verify` still produces a
  report.

`--format junit` and `--format markdown` work on `scan`, `diff`, `verify`,
`audit`, `sast`, and `doctor`. JUnit writes each unsuppressed finding as a
failed test case (severity in `type`) and each accepted finding as a skipped
one, for CI systems without SARIF support. Markdown writes a severity summary
and one table row per finding, for a pull request comment or the GitHub step
summary. Neither changes the exit code; use `--fail-on` for that.

```sh
securock audit --format junit --output securock.xml
securock verify --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Upload SARIF to GitHub code scanning:

```yaml
- run: securock verify --format sarif --output securock.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: securock.sarif
```

Machine-readable schemas live in the repository under
[`schemas/`](https://github.com/securock/securock/tree/main/schemas)
(`securock-lock`, `scan-report`, `diff-report`, `verify-report`,
`audit-report`, `sast-report`, `chain-report`, `doctor-report`,
`sbom-verify-report`).

## Typical workflow

1. Install Securock ([Install](/guide/install)).
2. From a project with a language lockfile, create a baseline:

   ```sh
   securock lock
   ```

   Offline first-time snapshots may need `--offline --no-fail` because
   unchecked vulns are `unknown`, not trusted. See
   [Quick start](/guide/quickstart).

3. Change dependencies the usual way (`npm install`, `cargo update`, …).
4. Inspect and gate the change:

   ```sh
   securock diff
   securock verify
   ```

5. When you accept the new trust state, record it:

   ```sh
   securock update --write
   ```

   `update` without `--write` previews the same report. `securock lock`
   also rewrites the lockfile, but without the review step or the refusal
   on untrusted artifacts.

## Next steps

- [Source code analysis](/guide/sast) — the `sast` command and its rules
- [Triage and exports](/guide/reports) — accept findings, export SBOM and VEX
- [Policy](/guide/policy) — default vs `strict`, custom YAML
- [Ecosystems](/guide/ecosystems) — which lockfiles and evidence depth
- [Evidence](/guide/evidence) — how to read evidence states
- [GitHub Action](/guide/action) — CI wiring
