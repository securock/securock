---
title: Usage
description: Securock CLI commands, flags, exit codes, and how scan differs from verify when enforcing trust policy and lockfile drift.
---

# Usage

Securock reads language lockfiles, applies a policy, and either writes
or compares against `securock.lock`.

```sh
securock scan [path]
securock lock [path]
securock diff [path]
securock verify [path]
securock explain PACKAGE [path]
securock audit [path]
securock doctor [path]
securock sbom export [path]
securock sbom verify SBOM [path]
securock accept FINDING-ID [path]
securock vex export [path]
securock version
```

`scan` is the default when no command is given. `trusted` means the
artifact passed the active policy, not that it is cryptographically
verified. The CLI prints this as `trusted (under active policy)`.

## Commands

| Command   | What it does                                                 |
| --------- | ------------------------------------------------------------ |
| `scan`    | Inspect the current tree under the active policy (default)   |
| `lock`    | Write a deterministic `securock.lock`                        |
| `diff`    | Show trust drift versus the lockfile                         |
| `verify`  | Fail on trust-relevant drift versus the lockfile             |
| `explain` | Print a trust checklist for one package                      |
| `audit`   | Report dependency findings ranked by severity                |
| `doctor`  | Check the project setup for security problems                |
| `sbom`    | Export the lockfile as an SBOM, or verify an SBOM against it |
| `accept`  | Accept a finding until a date, with a reason                 |
| `version` | Print the build version                                      |

### `sbom`

`sbom export` turns `securock.lock` into a software bill of materials on
stdout. It reads the lockfile, so run `securock lock` first and the SBOM
describes exactly what you locked.

```sh
securock sbom export > bom.cdx.json                  # CycloneDX 1.6 (default)
securock sbom export --spec spdx > bom.spdx.json     # SPDX 2.3
securock sbom verify bom.cdx.json                    # compare against securock.lock
```

- Each package carries a Package URL (`purl`) and, when the lockfile
  digest is a standard SHA-1/256/384/512, a `hashes` / `checksums` entry.
  Other digests, such as Go's `h1`, are kept as `securock:digest`.
- Trust evidence (status and reasons, provenance, signature, capabilities,
  ownership, source-to-build chain) is written as `securock:*` component
  properties in CycloneDX and as `securock:key=value` annotations in SPDX.
- Licenses recorded as release health are exported: a license expression made of known SPDX
  identifiers becomes a CycloneDX `expression` / SPDX `licenseDeclared`; any other text is a
  CycloneDX license name and stays out of `licenseDeclared`. The raw text is always kept as
  `securock:license`.
- Known vulnerabilities and malicious-package reports from the lockfile
  appear in the CycloneDX `vulnerabilities` list.
- The output is deterministic. Timestamps are left out unless
  `SOURCE_DATE_EPOCH` is set; SPDX, which requires a creation date, uses
  the Unix epoch otherwise.
- `sbom verify` reports a finding for each package that is missing,
  unexpected, or differs in version, purl, digest, or trust status (and
  for a policy digest mismatch in CycloneDX). It exits `1` on any
  finding and supports `--format json` (`sbom-verify-report` schema).
  It accepts SBOMs from other tools too, matching packages by purl.

### `accept`

`accept` records a finding you reviewed and decided to live with, so
`audit` stops failing on it until the date you give. Use the finding id
that `audit` prints.

```sh
securock accept known-vulnerability:GHSA-xxxx-xxxx-xxxx \
  --subject npm:lodash \
  --reason "only used in a build script, tracked in ENG-142" \
  --approver alice --expires 90d

securock accept list          # active and expired exceptions
securock accept remove known-vulnerability:GHSA-xxxx-xxxx-xxxx --subject npm:lodash
```

- `--reason` and `--expires` are required. `--expires` is a date
  (`2026-12-31`, the last day it applies, in UTC) or a number of days such
  as `90d`.
- `--subject` limits the exception to one package. `npm:lodash@4.17.20`
  matches that artifact; `npm:lodash` matches any version. Without it, the
  exception covers every package with that finding.
- For a vulnerability, `--justification` says it does not affect you rather than that you accept
  the risk: `component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, or
  `inline_mitigations_already_exist`. It only changes what [`vex export`](#vex) writes.
- Accepting the same finding and package again renews it.
- Exceptions live in `.securock/exceptions.yaml` (override with
  `--exceptions`). Commit the file and review it like code. It never
  changes `securock.lock` or any trust status; see
  [Trust model](/reference/trust-model#accepted-findings).
- `audit` keeps accepted findings in its output, marked suppressed
  (`suppressed` in JSON, `suppressions` in SARIF), and they do not count
  toward `--fail-on`. Once an exception expires the finding returns, with
  an `exception-expired` finding alongside it.

### `vex`

`vex export` writes the vulnerabilities you recorded with `accept` as a VEX document, so what
you decided about an advisory can travel with the SBOM:

```sh
securock vex export --author "Security Team" > product.openvex.json            # OpenVEX 0.2.0
securock vex export --author "Security Team" --spec cyclonedx > product.vex.json  # CycloneDX 1.6
```

- An exception with `--justification` becomes `not_affected`, with your reason as the impact
  statement. Any other becomes `affected` with an action statement, `Risk accepted by alice
until 2026-12-31: <reason>`: you are affected and have chosen to wait.
- Packages are named by purl. An exception that names no package covers every package in
  `securock.lock` that has the advisory; one with `--subject` covers only those.
- Expired exceptions, exceptions for advisories not in `securock.lock`, and exceptions that are
  not for a known vulnerability are left out. Packages with no purl (URL imports) are skipped.
- `--author` is required: a VEX document says who vouches for it. The timestamp is the current
  time, or `SOURCE_DATE_EPOCH` when set, which also makes the output reproducible.

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

### `scan` vs `verify`

These answer different questions:

- **`scan`** fails on **current** policy violations even when
  `securock.lock` already records them. Use it to keep the tree honest
  under today's policy.
- **`verify`** fails when the tree **drifts** from the accepted lockfile
  (digest, evidence, ownership, capabilities, trust reasons, and so on).
- **`diff`** is the operator view of the same comparison `verify` uses.

The GitHub Action default (`command: all`) runs `scan`, then `diff`,
then `verify`.

`explain PACKAGE` prints digest, source, provenance, signature, trust
chain, ownership, capabilities, vulnerabilities, and malicious-package
checks for one subject under the active policy.

`audit` turns scan evidence into findings: malicious packages are
`critical`, known vulnerabilities are `high`, and missing digests,
provenance or signatures rank lower. Evidence that was not checked is
reported as `info`, so offline runs always have `info` findings.

`doctor` checks the setup around securock: the lockfile and policy,
registry config (`.npmrc`, `.yarnrc.yml`, `nuget.config`) for plain
http, disabled TLS and literal credentials, workflow actions that are
not pinned to a commit SHA, and missing repository rulesets.

Both commands accept `--fail-on SEVERITY` (`critical`, `high`,
`medium`, `low` or `info`; default `high`) and exit `1` when a finding
is at or above it.

`audit` also takes `--min-release-age 7d`, which reports releases newer than that as high
findings; see [Release cooldown](/guide/evidence#release-cooldown).

## Shared flags

| Flag             | Meaning                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `--network`      | `public-only` (default), `offline`, or `allow-all`                                        |
| `--offline`      | Skip remote lookups; remote evidence stays `unknown`                                      |
| `--policy`       | Path to a policy file                                                                     |
| `--profile`      | Built-in policy: `default` or `strict` (not with `--policy`)                              |
| `--lock`         | Path to `securock.lock` (for `lock` / `diff` / `verify`)                                  |
| `--format`       | `text` (default), `json`, or `sarif`                                                      |
| `--output`       | Write the report to a file instead of stdout                                              |
| `--exceptions`   | Path to the accepted-findings file (`accept`, `audit`, `doctor`)                          |
| `--reachability` | Record scope and dependencies and mark vulnerabilities reachable, unreachable, or unknown |
| `--no-fail`      | Always exit `0`                                                                           |

`--offline` records vulnerability, malicious, capability, behavior,
ownership, provenance, signature, and chain evidence as `unknown`.

`--policy` and `--profile` are mutually exclusive. See
[Policy](/guide/policy) for profiles and YAML rules.

## Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| `0`  | Success / no trust drift (for `verify`) |
| `1`  | Trust violation                         |
| `2`  | Configuration or operational error      |

## JSON output

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
- `--format sarif` works on `scan`, `diff`, `verify`, `audit`, and `doctor`.
  Results point at `securock.lock` and name the package as a logical
  location. Each result has a stable `partialFingerprints` entry so code
  scanning can track it across runs. `--output` writes the file even when
  the command exits `1`, so a failing `verify` still produces a report.

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
`audit-report`, `doctor-report`, `sbom-verify-report`).

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

5. When you accept the new trust state, rewrite the lockfile:

   ```sh
   securock lock
   ```

## Next steps

- [Policy](/guide/policy) — default vs `strict`, custom YAML
- [Ecosystems](/guide/ecosystems) — which lockfiles and evidence depth
- [Evidence](/guide/evidence) — how to read evidence states
- [GitHub Action](/guide/action) — CI wiring
