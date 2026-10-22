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
securock version
```

`scan` is the default when no command is given. `trusted` means the
artifact passed the active policy, not that it is cryptographically
verified. The CLI prints this as `trusted (under active policy)`.

## Commands

| Command   | What it does                                               |
| --------- | ---------------------------------------------------------- |
| `scan`    | Inspect the current tree under the active policy (default) |
| `lock`    | Write a deterministic `securock.lock`                      |
| `diff`    | Show trust drift versus the lockfile                       |
| `verify`  | Fail on trust-relevant drift versus the lockfile           |
| `explain` | Print a trust checklist for one package                    |
| `audit`   | Report dependency findings ranked by severity              |
| `doctor`  | Check the project setup for security problems              |
| `sbom`    | Export the lockfile as an SBOM, or verify an SBOM against it |
| `version` | Print the build version                                    |

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

## Shared flags

| Flag        | Meaning                                                      |
| ----------- | ------------------------------------------------------------ |
| `--network` | `public-only` (default), `offline`, or `allow-all`           |
| `--offline` | Skip remote lookups; remote evidence stays `unknown`         |
| `--policy`  | Path to a policy file                                        |
| `--profile` | Built-in policy: `default` or `strict` (not with `--policy`) |
| `--lock`    | Path to `securock.lock` (for `lock` / `diff` / `verify`)     |
| `--format`  | `text` (default), `json`, or `sarif`                         |
| `--output`  | Write the report to a file instead of stdout                 |
| `--no-fail` | Always exit `0`                                              |

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
