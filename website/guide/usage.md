---
title: Usage
description: Securock CLI commands, flags, and exit codes — the lock, diff, verify, and update loop over securock.lock, plus audit, explain, doctor, JSON and SARIF output.
---

# Usage

Securock reads language lockfiles, applies a policy, and either writes
or compares against `securock.lock`.

```sh
securock scan [path]
securock lock [path]
securock diff [path]
securock update [path]
securock verify [path]
securock explain PACKAGE [path]
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
| `lock`    | Write a deterministic `securock.lock`                        | [Lockfile](/reference/lockfile)                             |
| `diff`    | Show trust drift versus the lockfile                         | [scan / verify](#scan-vs-verify)                            |
| `update`  | Review trust changes, then refresh the lockfile              | [update](#update)                                           |
| `verify`  | Fail on trust-relevant drift versus the lockfile             | [scan / verify](#scan-vs-verify)                            |
| `explain` | Print a trust checklist for one package                      | [explain](#explain)                                         |
| `audit`   | Report dependency findings ranked by severity                | [audit](#audit)                                             |
| `sast`    | Find vulnerabilities in your own source code                 | [Source code analysis](/guide/sast)                         |
| `chain`   | Correlate source findings into attack chains                 | [Source code analysis](/guide/sast)                         |
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
than that as high findings; see
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

## Shared flags

| Flag             | Meaning                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `--network`      | `public-only` (default), `offline`, or `allow-all`                                        |
| `--offline`      | Skip remote lookups; remote evidence stays `unknown`                                      |
| `--policy`       | Path to a policy file                                                                     |
| `--profile`      | Built-in policy: `default` or `strict` (not with `--policy`)                              |
| `--lock`         | Path to `securock.lock` (for `lock` / `diff` / `update` / `verify`)                       |
| `--format`       | `text` (default), `json`, or `sarif`                                                      |
| `--output`       | Write the report to a file instead of stdout                                              |
| `--exceptions`   | Path to the accepted-findings file (`accept`, `audit`, `sast`, `chain`, `doctor`)         |
| `--reachability` | Record scope and dependencies and mark vulnerabilities reachable, unreachable, or unknown |
| `--no-fail`      | Always exit `0`                                                                           |

`--offline` records vulnerability, malicious, capability, behavior,
ownership, provenance, signature, and chain evidence as `unknown`.

`--policy` and `--profile` are mutually exclusive. See
[Policy](/guide/policy) for profiles and YAML rules.

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

## Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| `0`  | Success / no trust drift (for `verify`) |
| `1`  | Trust violation                         |
| `2`  | Configuration or operational error      |

## JSON and SARIF output

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
