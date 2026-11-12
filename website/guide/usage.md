---
title: Usage
description: Securock CLI commands, flags, and exit codes — unified security checks for dependencies, source, secrets, and infrastructure, plus trust drift tracking and JSON and SARIF reports.
---

# Usage

Securock checks dependencies, source code, secrets, and infrastructure with
`security`. It also reads language lockfiles, applies a policy, and writes
or compares against `securock.lock` to track dependency trust drift.

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
securock security [path]
securock dast URL...
securock cspm [inventory.json...]
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

| Command    | What it does                                                              | More                                                        |
| ---------- | ------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `scan`     | Inspect the current tree under the active policy (default)                | [scan / verify](#scan-vs-verify)                            |
| `init`     | Detect lockfiles and write the first `securock.lock`                      | [init](#init)                                               |
| `lock`     | Write a deterministic `securock.lock`                                     | [Lockfile](/reference/lockfile)                             |
| `diff`     | Show trust drift versus the lockfile                                      | [scan / verify](#scan-vs-verify)                            |
| `update`   | Review trust changes, then refresh the lockfile                           | [update](#update)                                           |
| `verify`   | Fail on trust-relevant drift versus the lockfile                          | [scan / verify](#scan-vs-verify)                            |
| `explain`  | Print a trust checklist for one package                                   | [explain](#explain)                                         |
| `graph`    | Draw the dependency graph colored by trust status                         | [graph](#graph)                                             |
| `audit`    | Report dependency findings ranked by severity                             | [audit](#audit)                                             |
| `security` | Combine dependency, source, secret, infrastructure, and imported findings | [security](#security)                                       |
| `dast`     | Inspect live HTTP transport, security headers, and cookies                | [Live application checks](#live-application-checks-dast)    |
| `cspm`     | Audit recorded AWS cloud configuration and permissions                    | [Cloud security posture](#cloud-security-posture-cspm)      |
| `sast`     | Find vulnerabilities in your own source code                              | [Source code analysis](/guide/sast)                         |
| `chain`    | Correlate source findings into attack chains                              | [Source code analysis](/guide/sast)                         |
| `import`   | Bring another tool's SARIF results under securock's policy                | [import](#import)                                           |
| `doctor`   | Check the project setup for security problems                             | [doctor](#doctor)                                           |
| `sbom`     | Export the lockfile as an SBOM, or verify an SBOM against it              | [Triage and exports](/guide/reports#sbom-export-and-verify) |
| `accept`   | Accept a finding until a date, with a reason                              | [Triage and exports](/guide/reports#accept-findings)        |
| `vex`      | Export accepted vulnerabilities as OpenVEX or CycloneDX VEX               | [Triage and exports](/guide/reports#vex-export)             |
| `version`  | Print the build version                                                   |                                                             |

## Live application checks (`dast`)

```sh
securock dast https://app.example.com/ --network allow-all
securock dast https://app.example.com/login --network allow-all --timeout 10s
securock dast https://app.example.com/ --network allow-all --format sarif --output dast.sarif
securock security . --target https://app.example.com/ --network allow-all --dast-timeout 10s
```

`dast URL...` inspects one or more explicit URLs. `security --target URL` adds
live checks to the unified static/dependency report; repeat `--target` to
inspect more endpoints. `--timeout` on `dast` and `--dast-timeout` on `security`
set a positive total timeout per target (default `15s`, including redirects).
Without `--target`, `security` does not run DAST.

Checks include:

- Unencrypted HTTP and missing or disabled HTTPS HSTS.
- HTML responses without enforced CSP, framing protection, nosniff, or an
  explicit Referrer-Policy. Report-only CSP does not count as enforced CSP.
- Cookies without Secure, HttpOnly, or explicit SameSite, and SameSite=None
  cookies without Secure. Review cookie findings against the intended use;
  JavaScript-accessible cookies may be intentional.

This initial DAST implementation inspects response headers. It does not execute
JavaScript, crawl, authenticate, submit forms, test injection payloads, or prove
exploitability. Responses without HTML Content-Type are not checked for HTML
headers. It only observes cookies set on the requested response and redirects.
It is not an exhaustive test of the application's routes or vulnerabilities.

Both entry points require `--network allow-all` (or that mode in the policy).
Offline and public-only modes refuse all target requests. URL credentials,
queries, and fragments are rejected. Redirects stay within the original scheme,
host, and effective port, with a limit of five; even HTTP-to-HTTPS redirects
require scanning the final URL explicitly. TLS verification remains enabled.
No response bodies or cookie values are retained. See [Privacy](/reference/privacy#live-application-checks-dast).

`--fail-on` defaults to `high`; `--no-fail` suppresses severity failures only.
Network/TLS failures, exhausted redirects, out-of-scope redirects, and non-2xx
final responses (including login-required and not-found responses) produce
`dast:analysis-incomplete` and exit `2`. Completed results remain in the report,
including source findings in `security --target`. Every supplied target is
attempted even if an earlier target fails. Exceptions are loaded from the
current directory for `dast` and from the selected project for `security`;
`--exceptions` overrides either. Accept a live finding with its URL as subject:

```sh
securock accept dast:unencrypted-http --subject http://localhost:8080/ --reason 'Local development server' --expires 30d
```

Text, JSON (`dast-report.schema.json`), SARIF, JUnit, and Markdown formats are
supported. `--output` writes reports even when findings or incomplete scans
cause failure. Accepting an incomplete finding never suppresses the exit-2
operational error.

## Cloud security posture (`cspm`)

```sh
securock cspm inventory.json --offline
securock cspm inventory.json --offline --format json --output cspm.json
securock cspm --aws-region ap-northeast-1 --aws-profile audit --network allow-all
securock security . --cloud-inventory inventory.json --offline
securock security . --aws-region ap-northeast-1 --network allow-all
```

This initial CSPM implementation supports AWS Config recorded configuration.
Standalone `cspm` takes one or more JSON files; `security --cloud-inventory FILE`
is repeatable and merges cloud findings with dependency, source, and optional
DAST findings. Files are resolved from the current working directory. No cloud
collection runs unless `--aws-region` is supplied.

### Checks

| Resource type             | Recorded settings inspected                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `AWS::EC2::SecurityGroup` | IPv4/IPv6 world ingress to all protocols or TCP/UDP ports 22, 445, 1433, 3306, 3389, 5432, 6379, 9200, and 27017 |
| `AWS::RDS::DBInstance`    | Public accessibility, storage encryption, and automated backup retention                                         |
| `AWS::S3::Bucket`         | Public access block flags, public ACL groups, and wildcard principals in bucket policies                         |
| `AWS::IAM::Policy`        | Allow statements with wildcard actions and resources in the default policy version                               |
| `AWS::IAM::Role`          | Wildcard trust principals and wildcard inline-policy permissions                                                 |
| `AWS::CloudTrail::Trail`  | Multi-region configuration and log file validation                                                               |

IAM statements are evaluated independently; Deny statements do not grant access.
Policy conditions are noted as context; their effect is not evaluated and does
not lower the severity of wildcard-policy findings. Effective permissions, permission
boundaries, SCPs, account-level S3 blocks, other trails, and network reachability
are not evaluated. These checks neither certify compliance nor establish actual
exploitation or public reachability.

### Inventory and collection

Input must be an AWS Config snapshot with `configurationItems`, or an AWS CLI
`select-resource-config` response with JSON strings in `Results`. Configuration
may be a JSON object or JSON-encoded string. S3 supplementary
`PublicAccessBlockConfiguration`, `AccessControlList` (with `grants`), and
`BucketPolicy` (with `policyText`) are used when present. Otherwise those S3
checks remain unknown; the live query may not contain supplementary settings.
Unrecognized or missing fields are never interpreted as secure defaults.

For example:

```json
{
  "configurationItems": [
    {
      "resourceType": "AWS::RDS::DBInstance",
      "resourceId": "db-1",
      "accountId": "123456789012",
      "awsRegion": "ap-northeast-1",
      "configuration": {
        "publiclyAccessible": true,
        "storageEncrypted": true,
        "backupRetentionPeriod": 7
      }
    }
  ]
}
```

`--aws-region` uses an installed AWS CLI v2 and its existing credentials;
`--aws-profile` optionally selects a profile and requires `--aws-region`. AWS
Config recording must be enabled for the intended resource types in that region,
and the identity needs `config:SelectResourceConfig` permission. The CLI's normal
credential-provider permissions also apply. The fixed read-only SELECT query
uses auto-pagination, a 60-second total timeout, and a 16 MiB output cap. No cloud
resources are changed. Only allow-all network mode permits collection; offline
and public-only modes refuse it before invoking the CLI. See [Privacy](/reference/privacy#aws-cloud-posture-checks-cspm).

Exports are point-in-time evidence, and AWS Config live collection is still
recorded state. Freshness and full account/region coverage are not established;
`cspm:snapshot-scope` states that limitation in every evaluated inventory.
Unrepresented supported types produce `cspm:coverage-unavailable`, omitted
settings produce `cspm:check-unavailable`, and unsupported resources are explicit.
No returned resources does not mean the account is secure.

### Reports and failures

The usual text, JSON (`cspm-report.schema.json`), SARIF, JUnit, and Markdown formats
are supported. Findings include resource identity and remediation, without raw
configuration or policy documents. `--fail-on` defaults to `high`. Accepted
findings remain visible and are excluded from severity failures; use their
resource subject when accepting a cloud risk:

```sh
securock accept cspm:rds-public --subject AWS::RDS::DBInstance/123456789012/ap-northeast-1/db-1 --reason 'Reviewed endpoint' --expires 30d
```

Malformed/oversized inventories, duplicate identities within one inventory,
uncollected pages (`NextToken`), unavailable resource configurations, missing
AWS CLI/credentials, and failed collections exit `2`, including with `--no-fail`.
An inventory without any evaluable supported resources also exits `2`.
Completed findings remain in the report with `cspm:analysis-incomplete`, and
other supplied inventories are still processed. `--output` saves partial reports.
Standalone exceptions come from the current directory; unified exceptions come
from the selected project. `--exceptions` overrides either.

## The core commands

### `security`

Run all built-in security scanners together and review one report, sorted by
severity, with remediation advice and source dataflow traces:

```sh
securock security .
securock security . --offline
securock security . --fail-on medium --format json --output security.json
securock security . --format sarif --output security.sarif
securock security . --import semgrep.sarif --import trivy.sarif
```

Dependency auditing uses supported package-manager lockfiles in the selected
directory, including the policy's release cooldown and internal package names.
It honors `--policy`, `--profile`, `--network`, `--offline`, and `--reachability`.
Source analysis includes the SAST command's languages, secret detection, and IaC
rules; `--assume-params` enables its optional Go parameter heuristic.
`--import` accepts SARIF 2.1.0 and is repeatable (`-` reads standard input).

No `securock.lock` is required or written. Without a supported lockfile in the
selected directory, source checks still run and a
`security:dependencies-unchecked` info finding explains the missing coverage.
For a monorepo, run in each dependency project directory. Offline or private
dependency evidence stays unknown, with the same unchecked findings as `audit`.
Dependency auditing does not replace `verify` for detecting trust drift.

`--fail-on` defaults to `high`. One threshold and `.securock/exceptions.yaml`
apply to the entire report; use `accept` with the finding ID and subject to
record a reviewed risk. Accepted findings remain visible but do not fail CI.
Exit codes are `0` for no findings at the threshold, `1` for findings, and `2`
for operational errors. `--no-fail` suppresses severity failures only. If a
dependency scan fails, source findings are still written together with
`security:dependencies-incomplete`, and the command exits `2`.

Formats: text, JSON (`security-report.schema.json`), SARIF, JUnit, and Markdown.
Use `--output` to save a report, including reports from failed CI checks.

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

`audit` also reports a package listed in `rules.health.internal_names` that resolves
from a public registry as a high `dependency-confusion` finding; see
[Internal package names](/guide/policy#internal-package-names).

`audit --prioritize` looks up each matched advisory's CVEs in the CISA Known Exploited
Vulnerabilities catalog and the EPSS scores from FIRST. A vulnerability CISA lists as exploited
becomes `critical`, and one with an EPSS score of 50% or more is at least `high`; it never
lowers a severity, and a development-only dependency (with `--reachability`) stays `low`. The
finding keeps its ID, so `accept` still matches it. It is off by default because it contacts
two more hosts, sends only CVE IDs and skips on `--offline`: `audit` then reports an `info`
finding, `exploit-signals-unavailable`, instead of staying silent. See
[Privacy](/reference/privacy#exploitation-data-opt-in).

`audit --min-scorecard 5` reports a package whose source repository has an
[OpenSSF Scorecard](https://securityscorecards.dev) below that score (0 to 10) as a medium
`low-scorecard` finding. The repository comes from deps.dev, which gets it from the package's
own metadata, so the finding says when the link is not verified; a high score never counts
as a reason to trust a package, only a low one is reported. Only npm, PyPI, Cargo, Go, NuGet and
RubyGems packages from a public registry are looked up, and `--offline` skips it. Packages
with no score are counted in an `info` finding, `scorecard-unchecked`, because no score means
unknown, not safe. See [Privacy](/reference/privacy#openssf-scorecard-opt-in).

`audit --scorecard` does the same lookup without an overall minimum and applies the per-check
minimums from `rules.health.scorecard_checks`; see
[Scorecard checks](/guide/policy#scorecard-checks).

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
| `--no-fail`      | Suppress finding and trust failures; operational errors still exit `2`                      |

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
