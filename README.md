# Securock

**Security for dependencies, source code, secrets, and infrastructure.**

| [Docs](https://securock.dev) | [Install](#install) | [Quick start](#quick-start) | [Usage](#usage) | [Ecosystems](#supported-ecosystems) | [Privacy](docs/privacy.md) |
| ---------------------------- | ------------------- | --------------------------- | --------------- | ----------------------------------- | -------------------------- |

Language lockfiles pin versions. `securock.lock` pins the _trust
decision_ you accepted for those versions.

Securock records digest, provenance, signature, vulnerability,
malicious-package, capability, behavior, ownership, and trust-chain
evidence for each artifact, then fails CI when that trust state drifts.

Run `securock security` for a single security report across dependencies,
source code, committed credentials, and infrastructure configuration.
Review findings by severity, follow remediation advice, and use expiring
exceptions to record accepted risks.

```sh
securock security .
securock security . --offline
securock security . --format sarif --output security.sarif
securock security . --import other-scanner.sarif --fail-on medium
```

The security command uses existing package-manager lockfiles without writing
`securock.lock`. Source, secret, and infrastructure analysis runs offline;
dependency evidence follows the network policy. Unchecked evidence is explicit.
Without a supported lockfile in the selected directory, source analysis still
runs and dependency coverage is marked unchecked. Run in each dependency project
directory for a monorepo. `--fail-on` defaults to `high`; accepted findings do
not fail CI. Operational failures exit `2` even with `--no-fail`, and a failed
dependency scan preserves source results with an incomplete-analysis finding.
Text, JSON (`schemas/security-report.schema.json`), SARIF, JUnit, and Markdown
reports share the same findings and exceptions.

```text
securock lock     # snapshot the current tree
# …bump a dependency the way you already do…
securock diff     # see version, digest, evidence, and trust reasons
securock verify   # fail CI on the same drift
```

> `trusted` means the artifact passed the **active policy**. It is not a
> claim that a package is safe. Unchecked vulnerabilities are `unknown`,
> not trusted.

## Contents

- [Why](#why)
- [Features](#features)
- [Status](#status)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [GitHub Action](#github-action)
- [Supported ecosystems](#supported-ecosystems)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why

A dependency bump can change more than a version string: the artifact
digest, known vulnerabilities, or whether provenance is even present.
Those changes are easy to miss in a language lockfile diff.

## Features

**Lockfile and CI**

- Deterministic `securock.lock` (no timestamps, no absolute paths)
- `diff` / `verify` on artifact identity, not just package name
- GitHub Action that can run an attested release binary
- JSON reports (`--format json`) with exit `0` / `1` / `2`

**Evidence**

- npm: provenance, signatures, capabilities, granular behavior,
  ownership, and the source→build→artifact trust chain
- PyPI: Integrity API attestations (PEP 740), re-verified locally with
  Sigstore to provenance/signature `verified`
- OpenSSF Malicious Packages (`MAL-*`), recorded separately from CVEs
- Vulnerabilities carry CVSS-derived severity and the version that fixes them
- Release health (deprecated, release day, license) for npm and PyPI,
  typosquat-suspect names, optional `health` and `licenses` policy gates
- `explain` prints a trust checklist for one package
- `.pre-commit-hooks.yaml` provides `securock-verify` and `securock-audit` hooks for pre-commit
- `--recursive` runs `lock`, `scan`, `diff`, `verify`, and `audit` for every project in a monorepo, each with its own `securock.lock`
- `graph` draws the dependency graph as a tree, Mermaid, or DOT, colored by trust status

**Triage and policy**

- `accept` records reviewed findings with a reason and expiry in
  `.securock/exceptions.yaml`; `audit` suppresses them until they lapse
- `audit --min-release-age` (or `rules.health.min_release_age` in the policy) holds back releases that are too new
- `audit --prioritize` raises vulnerabilities that CISA lists as exploited (KEV) or that have an
  EPSS score of 50% or more; it is opt-in and only sends CVE IDs (see Privacy)
- `audit --min-scorecard 5` reports packages whose source repository has an OpenSSF Scorecard below
  that score (via deps.dev, opt-in); a score is only used to warn, never to vouch for a package
- `audit --scorecard` with `rules.health.scorecard_checks` in the policy sets a minimum for individual
  Scorecard checks such as `Dangerous-Workflow`
- `rules.health.internal_names` in the policy lists your private packages; `audit` flags one that
  resolves from a public registry as a `dependency-confusion` risk
- `--reachability` marks each vulnerability reachable, unreachable
  (development-only), or unknown from the dependency graph, so `audit`
  stops failing on test tooling

**Source code analysis** (`sast`)

- Tracks untrusted data (HTTP input, command-line arguments, standard
  input) through assignments, fields, closures, and calls across
  functions and files to SQL, command, code, path, NoSQL, request,
  response, and deserialization sinks (including zip slip and prototype
  pollution), and prints the path it took
- Follows deep call chains and loop-carried data to convergence,
  distinguishes receiver fields, and tracks setters, constructors, and
  direct local reference aliases; validation clears only the
  vulnerability classes it prevents, and an exhausted analysis budget
  is reported as incomplete
- Languages: Go, JavaScript/TypeScript, Python, Java, Kotlin, C#, PHP,
  and Ruby — fully offline
- Also analyzes packages vendored in `vendor/`, `node_modules/`, or
  `site-packages/`: a helper in an installed package is followed into
  the API it calls, but the package's own findings are not reported
- Also checks Dockerfiles, Kubernetes and Compose manifests, Terraform,
  and GitHub Actions workflows for unsafe settings, and scans every
  text file for committed credentials; a file it cannot parse is
  reported rather than skipped
- Benchmarks (not language-wide accuracy estimates; see
  [SAST benchmarks](docs/sast-benchmarks.md#javascript-typescript-and-php-source-regressions)
  and [how accurate is sast](https://securock.dev/guide/sast#how-accurate-is-sast)
  for labels, limitations, and reproduction commands):
  - Java on OWASP BenchmarkJava: 99.7% detected, 1.0% false positives
  - Python: 98.9% detected, 1.0% false positives
  - JavaScript on NodeGoat: 4/4 vulnerable cases, 0/1 safe controls flagged
  - TypeScript on Juice Shop: 4/4, 0/4
  - PHP on DVWA: 8/8, 0/3
  - PyGoat regression: 14/14 selected vulnerable cases, no alerts on
    two category-specific safe controls
  - Other languages are experimental

**Attack chains** (`chain`)

- Correlates the `sast` findings into attack chains: where attacker-
  controlled data enters, the dangerous operations it reaches, and the
  committed credentials an attacker could read on the way
- A chain from one dataflow finding's trace is `confirmed`; links that
  rely on findings sharing a file are `possible` and never fail a build,
  and a link is confirmed only when both findings are proven inside the
  same function — nothing unproven is reported as verified

**Other scanners** (`import`)

- Reads SARIF 2.1.0 from CodeQL, Semgrep, Trivy, Checkov and similar tools
  and treats the results like securock's own findings: ranked by severity,
  accepted through `securock accept`, and failing the build at `--fail-on`
- Severity comes from `security-severity`, then the SARIF level; a result
  with neither is `medium`. A suppression inside the SARIF file is not
  honored, so only the exceptions file accepts a finding
- `sast --import report.sarif` merges such a report into the sast report instead, for one list and one exit code

**Exports**

- CycloneDX 1.6 / SPDX 2.3 SBOM export with trust evidence, and
  `sbom verify` against the lockfile
- `vex export` turns accepted vulnerabilities into OpenVEX or CycloneDX VEX

**Privacy**

- Default network mode is `public-only`: private registries,
  `GOPRIVATE` / `GONOPROXY` modules (including `go env -w`), and custom
  or ambiguous `GOPROXY` lists stay on-machine ([privacy](docs/privacy.md))

## Status

Pre-1.0. All resolvers are stable.

- **npm, pnpm, Yarn, Bun, Deno** collect provenance, signature, capability,
  behavior, ownership, and trust-chain evidence from the npm registry.
- **PyPI (uv / Poetry / PDM / Pipenv)** collects Integrity API attestations and
  locally re-verifies PEP 740 Sigstore envelopes to provenance/signature
  `verified` when the signer identity, filename, digest, signature, and
  transparency log check out.
- **Other resolvers** query OSV when their package source can be proven
  public. Otherwise vulnerability and malicious-package evidence remain
  `unknown`, and unsupported evidence axes stay `unknown`.

### Compatibility

`version: 1` and `version: 2` lockfiles are migrated to `version: 3` in
memory on `diff` / `verify`. Run `securock lock` to write a refreshed v3
file.

A v3 file is refused by older releases (they decode strictly), so update
every machine and CI job that runs securock before committing one.

## Install

### Script

```bash
curl -fsSL https://securock.sh/install | sh
```

The installer checks SHA-256. Unless `SKIP_ATTESTATION=1` is set, it
also requires `gh` and verifies GitHub attestations.

```bash
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```

### Homebrew

HEAD, builds from this repo:

```bash
brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock
```

### From source

```bash
go install github.com/securock/securock/cmd/securock@latest
```

## Quick start

```bash
git clone https://github.com/securock/securock.git
cd securock/examples/npm

securock lock --offline --no-fail
securock verify --offline

cp after/package-lock.json package-lock.json
securock diff --offline
securock verify --offline   # fails until you accept the new tree
```

`--offline` skips OSV and registry lookups. The default policy treats
unchecked vulnerabilities and malicious reports as `unknown`, so the
first `lock` needs `--no-fail`. The committed `securock.lock` in that
directory is that snapshot.

The same loop is available for pnpm, Yarn, Bun, uv, Poetry, Go, and
Cargo under [`examples/`](examples/).

## Usage

### Commands

| Command            | What it does                                                |
| ------------------ | ----------------------------------------------------------- |
| `securock scan`    | Inspect the tree (default if you pass no command)           |
| `securock lock`    | Write `securock.lock`                                       |
| `securock diff`    | Show trust drift vs the lockfile                            |
| `securock update`  | Review trust changes, then refresh the lockfile             |
| `securock verify`  | Fail on trust-relevant drift                                |
| `securock init`    | Detect lockfiles and write the first `securock.lock`        |
| `securock explain` | Explain why a package is trusted                            |
| `securock graph`   | Draw the dependency graph colored by trust status           |
| `securock audit`   | Report dependency findings by severity                      |
| `securock security` | Audit dependencies, source code, secrets, and infrastructure together |
| `securock dast` | Inspect live HTTP transport, security headers, and cookies |
| `securock cspm` | Audit recorded AWS cloud configuration and permissions |
| `securock sast`    | Find vulnerabilities in your own source code                |
| `securock chain`   | Correlate source findings into attack chains                |
| `securock import`  | Bring another tool's SARIF results under securock's policy  |
| `securock doctor`  | Check the project setup for security problems               |
| `securock sbom`    | Export `securock.lock` as CycloneDX or SPDX, or verify one  |
| `securock accept`  | Accept a finding until a date, with a reason                |
| `securock vex`     | Export accepted vulnerabilities as OpenVEX or CycloneDX VEX |
| `securock version` | Print the build version                                     |

### Live application checks (DAST)

Inspect explicitly selected URLs with bounded GET requests:

```sh
securock dast https://app.example.com/ --network allow-all
securock dast https://app.example.com/ --network allow-all --timeout 10s --format json
securock security . --target https://app.example.com/ --network allow-all
```

DAST checks unencrypted HTTP, HTTPS HSTS, HTML CSP and framing protection,
HTML nosniff and referrer headers, and Cookie Secure/HttpOnly/SameSite attributes.
These are response-configuration findings, not proof of exploitable XSS or CSRF.
It uses the existing exceptions, severity thresholds, and output formats.
DAST JSON uses `schemas/dast-report.schema.json`; combined results use the
security report schema. Cookie values and response bodies are not reported.

DAST requires allow-all mode and refuses offline/public-only mode. It never
crawls, submits forms, sends injection payloads, or authenticates. Up to five
same-origin redirects are followed; cross-origin redirects, HTTP errors,
timeouts, and TLS failures produce incomplete-analysis findings and exit `2`,
even with `--no-fail`. Target URLs cannot contain credentials, queries, or
fragments. See [Privacy](docs/privacy.md#live-application-checks-dast).

### Cloud security posture (CSPM)

Inspect an AWS Config snapshot offline, or collect recorded configuration with
an existing AWS CLI v2 setup:

```sh
securock cspm inventory.json --offline
securock cspm --aws-region ap-northeast-1 --aws-profile audit --network allow-all
securock security . --cloud-inventory inventory.json --offline
securock security . --aws-region ap-northeast-1 --network allow-all
```

The initial AWS checks cover S3 public access settings/ACLs/policies, internet
access to administrative or database ports in EC2 security groups, RDS public
access/encryption/backups, broad IAM policies and trust principals, and CloudTrail
region coverage/log validation. Missing settings and unrepresented resource types
are reported as unknown. Reports use the existing exceptions, severity thresholds,
and formats, with `schemas/cspm-report.schema.json` for standalone JSON.

Input accepts AWS Config `configurationItems` snapshots or CLI
`select-resource-config` JSON `Results`. Live collection requires AWS Config
recording, `config:SelectResourceConfig` permission, and allow-all network mode.
It is read-only, limited to the selected region's recorded resources, and cannot
establish account-wide completeness or freshness. No cloud settings are changed.
Effective permissions, reachability, and compliance are not proven by these
configuration checks. See [Privacy](docs/privacy.md#aws-cloud-posture-checks-cspm).

### Flags

| Flag / exit             | Meaning                                                                                                                            |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `--network public-only` | Default. Public registries only (`offline`, `allow-all` also valid)                                                                |
| `--offline`             | Skip remote lookups; remote evidence stays `unknown`                                                                               |
| `--policy`              | Path to a policy file                                                                                                              |
| `--profile`             | Built-in policy profile: `default` or `strict` (not with `--policy`)                                                               |
| `--lock`                | Path to `securock.lock` (for `lock` / `diff` / `update` / `verify`)                                                                |
| `--format json`         | Stable JSON on `scan`, `diff`, `verify`, and `explain`                                                                             |
| `--format sarif`        | SARIF 2.1.0 on every report command, for GitHub code scanning                                                                      |
| `--format junit`        | JUnit XML on `scan`, `diff`, `verify`, `audit`, `sast`, and `doctor`                                                               |
| `--format markdown`     | A pull request comment table on the same commands                                                                                  |
| `--recursive`, `-r`     | `lock`, `scan`, `diff`, `verify`, `audit`. Run for every project under the path                                                    |
| `--no-cache`            | Do not read or write the on-disk response cache; `--cache-ttl` sets its lifetime (default `1h`), `securock cache clear` empties it |
| `--output`              | Write the report to a file instead of stdout (also on exit `1`)                                                                    |
| `--min-release-age`     | `audit`. Report npm and PyPI releases newer than this, such as `7d`                                                                |
| `--prioritize`          | `audit`. Raise vulnerabilities in CISA KEV or with EPSS of 50% or more; sends CVE IDs to OSV, CISA and FIRST                       |
| `--min-scorecard`       | `audit`. Report packages whose source repository has an OpenSSF Scorecard below this score (0 to 10); sends names to deps.dev      |
| `--scorecard`           | `audit`. Look up Scorecards and apply `rules.health.scorecard_checks` from the policy; sends names to deps.dev                     |
| `--fail-on`             | `audit`, `sast`, `chain`, `import` and `doctor`. Exit `1` at or above this severity (default `high`)                               |
| `--assume-params`       | `sast` and `chain`. Treat string parameters of Go functions nothing calls directly as untrusted (registry handlers)                |
| `--import`              | `sast` / `security`. Merge another scanner's SARIF report into the combined report (repeatable)                                                     |
| `--exceptions`          | Accepted-findings file (default `.securock/exceptions.yaml`)                                                                       |
| `--reachability`        | Record package scope and dependencies; mark vulnerabilities reachable, unreachable, or unknown                                     |
| `--no-fail`             | Suppress finding and trust failures; operational errors still exit `2`                                                                                                                    |

### Exit codes

| Exit | Meaning                            |
| ---- | ---------------------------------- |
| `0`  | Success / no trust drift           |
| `1`  | Trust violation                    |
| `2`  | Configuration or operational error |

### Example lockfile

```yaml
# securock.lock (abridged)
version: 3
artifacts:
  - subject:
      ecosystem: npm
      name: react
    version: 19.2.0
    digest: sha256:...
    source:
      resolver: npm
      registry: https://registry.npmjs.org
    evidence:
      provenance: unknown
      signature: unknown
      vulnerabilities:
        state: unknown
      malicious:
        state: unknown
      capabilities:
        state: checked
        network: false
        filesystem: none
        environment: false
        shell: false
        native_code: false
        install_scripts: false
      behavior:
        state: checked
      ownership:
        state: checked
        publisher: alice <alice@example.com>
        maintainers:
          - alice
      chain:
        state: present
        source: github.com/facebook/react
        commit: abc123
        workflow: release.yml
    trust:
      status: unknown
```

## GitHub Action

Pin the action to a commit SHA.

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
          command: all # scan+diff+verify (default); also scan, diff, verify, both
          # profile: strict
          # policy: .securock/policy.yaml
```

Default `command: all` runs `scan` (current policy violations), then
`diff` and `verify` (trust drift). Use `both` for drift-only checks.
`policy` and `profile` are mutually exclusive.

The action writes a trust report to `$GITHUB_STEP_SUMMARY` even when
it cannot comment on a fork PR.

## Supported ecosystems

### Stable

| Ecosystem | Resolver  | Lockfile               |
| --------- | --------- | ---------------------- |
| npm       | npm       | `package-lock.json`    |
| npm       | pnpm      | `pnpm-lock.yaml`       |
| npm       | yarn      | `yarn.lock`            |
| npm       | bun       | `bun.lock`             |
| npm       | deno      | `deno.lock`            |
| jsr       | deno      | `deno.lock`            |
| url       | deno      | `deno.lock`            |
| cargo     | cargo     | `Cargo.lock`           |
| go        | go        | `go.mod` + `go.sum`    |
| pypi      | uv        | `uv.lock`              |
| pypi      | poetry    | `poetry.lock`          |
| pypi      | pdm       | `pdm.lock`             |
| pypi      | pipenv    | `Pipfile.lock`         |
| packagist | composer  | `composer.lock`        |
| rubygems  | bundler   | `Gemfile.lock`         |
| nuget     | nuget     | `packages.lock.json`   |
| swift     | swiftpm   | `Package.resolved`     |
| cocoapods | cocoapods | `Podfile.lock`         |
| conan     | conan     | `conan.lock`           |
| cran      | renv      | `renv.lock`            |
| julia     | julia     | `Manifest.toml`        |
| hackage   | cabal     | `cabal.project.freeze` |
| pub       | pub       | `pubspec.lock`         |
| hex       | mix       | `mix.lock`             |
| maven     | gradle    | `gradle.lockfile`      |

Notes:

- **Deno** — `deno.lock` v5 is the stable target; v3/v4 are supported
  for compatibility. npm packages use OSV and npm evidence. JSR and
  HTTPS URL artifacts are stable to parse; OSV does not cover them yet,
  so vulnerability state stays `unknown`.
- **Gradle** — records Maven coordinates from `gradle.lockfile` but
  does not prove a registry, so OSV is not queried in `public-only`.
- **Cabal** — reads `cabal.project.freeze`. OSV is queried in `public-only`
  only when Hackage is the sole proven repository.
- **Julia** — reads `Manifest.toml`. No registry is proven, so OSV is not
  queried in `public-only`.
- **renv** — reads `renv.lock`. Only `CRAN` packages from the public CRAN
  hosts are sent to OSV; other repositories stay `unknown`.
- **Conan** — reads Conan 2 `conan.lock`. No registry is proven and OSV has
  no ConanCenter ecosystem, so vulnerability state stays `unknown`.
- **CocoaPods** — reads `Podfile.lock`. OSV has no CocoaPods ecosystem, so
  vulnerability state stays `unknown`.

## Documentation

- [Lockfile specification](docs/specification.md)
- [Trust model](docs/trust-model.md)
- [Privacy](docs/privacy.md)
- [Threat model](docs/threat-model.md)
- [GitHub rulesets](docs/github-rulesets.md)

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md).

```bash
go test ./...
go test -race ./...
go vet ./...
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/),
lowercase subject only.

## Security

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/securock/securock/security/advisories/new).
Do not open a public issue for an unreleased vulnerability.
See [SECURITY.md](SECURITY.md).

## License

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSE) file for details.

## Finding baselines

Save comparable JSON finding reports and run `securock baseline before.json after.json`.
Only new occurrences and severity changes count toward `--fail-on`; scan tools
must match. IDs, subjects and source files are matched without line numbers.
Incomplete/unchecked evidence remains visible. Missing findings are unobserved,
not certified fixed: compare identical scanner settings and scope. Standard finding
formats are supported; JSON retains the current report's tool and schema.

## Scan coverage

`securock security . --coverage-output coverage.json` writes the requested live
targets, recorded AWS account/regions, and incomplete/unchecked evidence to a
separate JSON file (`coverage-report.schema.json`). Attempted scopes do not
certify exhaustive source or route coverage; every gap remains visible.

## Container images

`securock container IMAGE --network allow-all` runs installed Trivy to scan OS
packages, application dependencies, and secrets, importing its SARIF findings.
`securock container image.tar --archive --offline` uses local input and existing
Trivy databases with database updates disabled. Missing scanners/databases fail
with exit 2. Exceptions, severity gates and finding formats apply. JSON uses
`container-report.schema.json`. Image registries and Trivy database endpoints
are contacted only in enabled network mode; configure registry credentials in
Trivy's normal environment.

## Remediation assistance

`securock remediate report.json --project .` lists actionable fixes and recommended
versions already included in findings. `--patch-dir patches` drafts narrowly
supported Go TLS-verification fixes, refusing stale locations and paths outside
the project. Review patches before `git apply --unidiff-zero`; source files are
never automatically changed. `--verify` reruns offline SAST, emits its full report
and gates new high source findings. It does not certify dependency, cloud or DAST
remediation: rerun their original commands with identical scopes.

## Extended DAST

`securock dast https://app.example/ --network allow-all --bearer-env APP_TOKEN`
reads authentication from the environment without writing it to reports.
`--openapi api.json` expands up to 100 static GET paths from local OpenAPI 3 JSON;
parameterized paths are explicitly reported as incomplete. Only the supplied
origin is used; OpenAPI server declarations cannot redirect scans.
`--browser` additionally uses installed Node.js, Playwright and Chromium to inspect
rendered forms. Browser requests are limited to 100 same-origin GET/HEAD requests;
mutating, cross-origin and WebSocket requests are blocked and reported as gaps.
Browser or dependency failures exit 2. This executes application JavaScript and
therefore belongs on authorized test environments. Existing header-only DAST
remains available without browser dependencies.

Set `SECUROCK_CHROMIUM_PATH` to use an existing Chromium executable instead of Playwright's bundled browser.

## Multiple cloud scopes

`cspm` and `security` accept repeatable `--aws-scope audit@us-east-1`,
`--azure-subscription SUBSCRIPTION_ID` and `--gcp-project PROJECT_ID` with
`--network allow-all`. Installed AWS CLI, Azure CLI with Resource Graph, and
gcloud use their existing credentials and read-only queries. Every requested
scope is attempted; collection failures remain visible and exit 2.
Offline inventories also accept native Azure Resource Graph `data` responses
and GCP Cloud Asset resource arrays. Initial Azure rules cover storage access
and public administrative NSG rules; GCP rules cover public administrative
firewall access and bucket access controls. Missing properties remain unknown.
Azure pagination tokens fail closed: provide complete exports if a subscription
exceeds the 1000-resource query limit. No provider settings are modified.
Save comparable JSON reports and use `baseline` to detect newly observed cloud
risks. This does not track every benign configuration change or prove resolution.

## Continuous monitoring

`securock watch . --interval 1h --state monitor.json -- --offline` repeatedly
runs unified scans and prints newly observed findings. Use `--runs 1` for cron
or another scheduler; `--runs 0` continues until cancellation. Scope-specific
security flags follow `--`, for example cloud inventory or live target flags.
Operational scan errors retain the previous baseline. Successful scans retain
unobserved risks in state and never claim missing risks are fixed. State is stored with private permissions and atomic replacement.
`--webhook-env SECURITY_WEBHOOK --network allow-all` posts new unsuppressed
findings at the `--fail-on` threshold as a Securock JSON report to an HTTPS
receiver. The URL comes from the environment and is not printed. Configure your
receiver to route alerts to an owner or team; this is a generic JSON webhook,
not a Slack-specific payload. Delivery failures exit 2 without advancing state.
Do not run multiple writers against the same state file.

## Scan execution records

`security . --offline --record run.json --scope-id billing-api` saves the
engine/build identity, Git revision/dirty status, configuration and policy
fingerprint, source-file inventory, source coverage status and report digest.
There are no wall-clock timestamps or absolute source paths. Raw flag values
are hashed rather than stored. Records are point-in-time scan evidence, not
proof of runtime safety; anonymous scopes cannot certify comparable coverage.
Development builds use an executable fingerprint when version metadata is unknown.
Record checksums detect accidental changes, not producer authenticity; use trusted
CI artifacts and protect records as security evidence.

## Finding lifecycle and responsibility

`triage run.json --state issues.json --format json` maintains stable occurrence
keys and new/active/resolved/reopened/unobserved states. Only matching engine,
configuration and explicit complete source scope, with the source file present
in both inventories, can resolve a missing SAST finding. Other missing findings
remain unobserved. Reprocessing the same record is idempotent.
Use `--finding KEY --owner TEAM --due YYYY-MM-DD` to assign responsibility and
`--as-of YYYY-MM-DD` to evaluate overdue status without machine-clock output.
State is private JSON, atomically replaced; use a single writer per registry.

## Contextual risk priority

`prioritize report.json --assets assets.json --format json` ranks all findings
without changing their original severity or CI threshold. Asset context uses
`{"version":1,"assets":[{"match":"src/payments/","owner":"payments","criticality":5,"internet_exposed":true,"reachable":true,"evidence":["inventory:edge-service"]}]}`.
Matches are explicit subject prefixes (longest wins), with criticality 1–5.
Optional `privileged` and `known_exploited` signals also raise the score. Every
asset requires evidence references; missing signals remain unknown. References
are not fetched or independently verified, and no attack chain is inferred from
co-location. Accepted findings remain visible at priority zero.
JSON follows `priority-report.schema.json`.

## Organization policy

`enforce report.json --organization org.json --service api --as-of 2030-01-01`
applies service ownership, SLA dates, severity gates and exception review limits.
The policy is version 1 JSON with `services.api` containing `owner`,
`criticality` (1–5), `fail_on`, `sla_days` (severity to positive days),
`require_approver`, `reviewers`, and `max_exception_days`.
`security --org-policy org.json --service api --policy-date 2030-01-01` applies
the same gate during scanning. A CLI severity flag can strengthen but cannot
weaken the organization threshold. Unapproved or overly long exceptions are
unsuppressed and generate a high policy finding. Explicit dates keep decisions
reproducible. Organization policy does not silently allow public resources; use
reviewed, expiring exceptions with permitted approvers for intentional exposure.
Approver names are declared metadata, not authenticated human signatures. Protect
organization and exception files with authenticated repository review.
Standalone JSON follows `organization-report.schema.json` and includes task
owners and due dates. Normal `--no-fail` remains available for report generation.

## Reproducible integration validation

`integration --local --format json` starts a temporary loopback HTTP fixture and
checks actual source, AWS export and HTTP scanner results against expected rule
IDs. Temporary files and the server are cleaned up. It needs loopback networking
but no external service or credentials.
`integration suite.json --network allow-all` validates prepared test cloud
accounts, images or applications with installed provider tools. The version 1
suite contains `steps`, each with unique `name`, read-only scanner `command`
(`security`, `dast`, `cspm`, `container`), `args`, `expected` and `forbidden` rule
ID arrays. Output redirection and nested orchestration commands are rejected.
The outer network mode is enforced. No infrastructure is provisioned, changed
or deleted; supply isolated test resources and read-only credentials. Missing
expected findings, forbidden findings and scanner errors fail the suite.
JSON results follow `integration-report.schema.json`. Cloud and container steps
run only when explicitly configured; local fixtures do not establish provider
API compatibility.

## Secrets in Git history

`history . --offline` scans unique text blobs reachable from HEAD in memory,
including removed files and document files. `--all-refs` includes every local
ref; `--revision COMMIT` selects a different tip. Partial clones are refused and shallow boundaries fail closed. Git lazy fetching
and interactive prompts are disabled. No remote fetch, checkout,
credential validation, revocation or history rewrite occurs. Findings show blob
identity, path and an observed commit, never matched credential values.
`--max-commits` (1000) and `--max-blobs` (10000) bound work; budget exhaustion
exits 2 with partial findings. Files over 512 KiB are explicitly unchecked.
Binary content, submodule content, unreachable objects, reflogs and LFS payloads
are outside the scan. Detection is pattern-based and does not prove validity.
`security . --git-history --offline` includes the default HEAD history scan in
the unified report. Standalone JSON follows `history-report.schema.json`.

## Offline security dashboard

`dashboard issues.json --run before.json --run after.json --as-of 2030-01-03 --output dashboard.html`
renders a self-contained interactive HTML work queue from lifecycle state and
validated execution records. Filter by lifecycle state, severity, owner, deadline
or text; inspect remediation and coverage gaps, and compare observed high-severity
counts across records supplied in chronological order. Different scope/coverage
can change counts without an actual risk improvement. Overdue dates use the
explicit as-of date or stored triage flags, not the viewing computer's clock.
The report makes no external requests and needs no hosted service, CDN, font,
JavaScript package or telemetry. User content is escaped and scripts are CSP
hash-allowlisted. Protect exported HTML as project security data.

## Enterprise identity

`identity oidc.json --token-env SECUROCK_TOKEN` verifies an RS256 OIDC access
token using pinned RSA JWKS keys, an exact HTTPS issuer and API audience, expiry
and not-before claims. The JSON config contains `issuer`, `audience`, `keys`
(a JWKS `keys` array), and `bindings` (`subject`, `tenant`, `roles`). Roles are
admin, reader, developer, reviewer, runner and provisioner. Unknown subjects and
algorithms fail closed. Tokens are read only from the environment and never printed.
JSON output follows `identity-report.schema.json`.

Use an API audience, not an ID token intended for another client. Operate MFA
and SAML federation in your IdP; SAML-only deployments require an OIDC identity
broker. Native SAML assertion processing is not provided. Key rotation is explicit:
pin overlapping trusted keys, restart services, then remove retired keys. Identity
verification makes no network requests and works offline.
