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
securock update [path]
securock verify [path]
securock explain PACKAGE [path]
securock audit [path]
securock sast [path]
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
| `update`  | Review trust changes, then refresh the lockfile              |
| `verify`  | Fail on trust-relevant drift versus the lockfile             |
| `explain` | Print a trust checklist for one package                      |
| `audit`   | Report dependency findings ranked by severity                |
| `sast`    | Find vulnerabilities in your own source code                 |
| `doctor`  | Check the project setup for security problems                |
| `sbom`    | Export the lockfile as an SBOM, or verify an SBOM against it |
| `accept`  | Accept a finding until a date, with a reason                 |
| `version` | Print the build version                                      |

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
- CycloneDX output is deterministic: it has no timestamp. SPDX requires a creation time and
  uses the current time. Set `SOURCE_DATE_EPOCH` to stamp either format with a fixed time and
  make both reproducible.
- `sbom verify` reports a finding for each package that is missing,
  unexpected, or differs in version, purl, digest, or trust status (and
  for a policy digest mismatch in CycloneDX). It exits `1` on any
  finding and supports `--format json` (`sbom-verify-report` schema).
  It accepts SBOMs from other tools too, matching packages by purl. In SARIF output, results
  point at the SBOM file.

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
  not for a known vulnerability are left out. Packages with no purl (URL imports) are skipped. If
  nothing is left, the command fails instead of writing an empty document, since an OpenVEX
  document needs at least one statement.
- In the CycloneDX form, each affected package is declared as a component with its purl as
  `bom-ref`, so every reference resolves within the document.
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

`sast` analyzes the project's own source, offline, and reports untrusted data
that reaches a dangerous call along with the path it took. It reads Go,
JavaScript and TypeScript (`js`), Python (`py`), Java (`java`), Kotlin (`kt`), C# (`cs`),
PHP (`php`), and Ruby (`rb`). Rule ids are `sast:LANGUAGE/RULE`:

| Rule                           | CWE  | Severity | Languages               |
| ------------------------------ | ---- | -------- | ----------------------- |
| `sql-injection`                | 89   | high     | all                     |
| `command-injection`            | 78   | high     | all                     |
| `path-traversal`               | 22   | high     | all                     |
| `xpath-injection`              | 643  | high     | all but Go              |
| `ldap-injection`               | 90   | high     | all but Go              |
| `ssrf`                         | 918  | medium   | all                     |
| `xss`                          | 79   | medium   | all                     |
| `open-redirect`                | 601  | medium   | all                     |
| `regex-injection`              | 1333 | medium   | all but Go              |
| `nosql-injection`              | 943  | high     | all                     |
| `prototype-pollution`          | 1321 | high     | JS                      |
| `zip-slip`                     | 22   | high     | Python                  |
| `template-autoescape-disabled` | 79   | medium   | JS, Python              |
| `log-injection`                | 117  | low      | all                     |
| `cors-misconfiguration`        | 942  | medium   | all but PHP, Ruby       |
| `insecure-random`              | 338  | medium   | all                     |
| `toctou`                       | 367  | low      | all                     |
| `code-injection`               | 94   | critical | all but Go              |
| `insecure-deserialization`     | 502  | high     | all but Go              |
| `weak-crypto`                  | 327  | medium   | all                     |
| `tls-verification-disabled`    | 295  | medium   | all                     |
| `jwt-unverified`               | 347  | high     | JS, Python, Java, Ruby  |
| `hardcoded-signing-key`        | 321  | high     | JS, Java                |
| `hardcoded-key`                | 321  | medium   | all but Ruby            |
| `permit-all`                   | 862  | high     | Java                    |
| `xxe`                          | 611  | high     | Python, Java, PHP, Ruby |
| `debug-enabled`                | 489  | medium   | Python, PHP, Ruby       |
| `insecure-cookie`              | 614  | medium   | all but Ruby, PHP       |
| `https-not-enforced`           | 319  | medium   | Ruby                    |
| `electron-insecure-window`     | 1021 | high     | JS                      |
| `mass-assignment`              | 915  | medium   | JS, Ruby                |
| `weak-allowlist`               | 601  | medium   | JS, Python, Java, Ruby  |
| `directory-listing`            | 548  | medium   | JS                      |
| `prompt-injection`             | 1427 | medium   | JS, Python              |
| `csrf-disabled`                | 352  | medium   | Ruby, Java, Python, C#  |
| `variable-extraction`          | 621  | high     | PHP                     |
| `insecure-temp-file`           | 377  | low      | Python                  |
| `world-writable`               | 732  | medium   | all                     |
| `hardcoded-secret`             | 798  | medium   | Go                      |

Annotations and decorators are read where they matter: Spring `@CrossOrigin` with
`allowCredentials` for any origin, Django `@csrf_exempt` and Flask `@csrf.exempt`, and an
ASP.NET MVC `[HttpPost]` action without `[ValidateAntiForgeryToken]` (not in an
`[ApiController]`, and not when the class has `[AutoValidateAntiforgeryToken]`).

`debug-enabled` is not reported inside a branch that asks which environment the code runs in
(`env.IsDevelopment()`, `NODE_ENV`, `FLASK_ENV`), since that is where debug settings belong.

The `weak-crypto`, `tls-verification-disabled` and similar rules need no untrusted
data: they flag the call (`hashlib.md5`, `requests.get(verify=False)`,
`MessageDigest.getInstance("MD5")`, `curl_setopt` with `CURLOPT_SSL_VERIFYPEER`
false, `Digest::MD5`) by its arguments. A call that states
`usedforsecurity=False` is not flagged.

`sast:analysis-incomplete` (info) marks a file that could not be analyzed.

Three of these depend on what the data can be. `nosql-injection` fires when a
request object reaches a query filter (`User.findOne({name: req.body.name})`,
`users.find_one({"name": request.json["name"]})`), or when request text is parsed
into a query (`Document.parse`). It does not fire for values that are always strings:
a path parameter, a header, a Flask form field, a Java `getParameter`. Casting with
`String(...)` clears it. In Go it covers the MongoDB driver and needs the module to be
downloaded. `insecure-random` flags a predictable generator (`Math.random`, `random.*`,
`math/rand`, `rand`, `java.util.Random`) only where the result is named like a secret
(a token, password, session, nonce, salt, key, OTP), either in the variable or the
function name. `toctou` flags a destructive file operation on a path that the same
function checked earlier (`os.Stat` then `os.Remove`); idempotent creation such as
`MkdirAll` is not flagged. `cors-misconfiguration` flags an `Access-Control-Allow-Origin`
header filled from the request, and `cors({origin: true, credentials: true})`. `xxe` in
Java flags a parser factory created without disabling DTDs or external entities in the
same function. `prototype-pollution` fires when request data reaches a deep merge
(`_.merge`, `deepmerge`, `$.extend(true, ...)`), a `_.set` path, a nested
`obj[a][b] = v` write, or a hand-written recursive merge (`merge(t[k], s[k])` inside
`merge`). `log-injection` is rated low so it does not fail the default `--fail-on high`;
newline stripping, `JSON.stringify` and quoting clear it.

Zip slip is reported as `path-traversal` when an archive entry name (Go `zip.File.Name` and
`tar.Header.Name`, Python `namelist()` and `ZipInfo.filename`, Java `ZipEntry.getName()`,
`entry.path` in Node, PHP `getNameIndex`, Ruby `entry.name`) reaches a file operation. A
check that keeps the path inside the destination ends it: `filepath.IsLocal`, rejecting
`..`, a prefix check on a cleaned path, or `startsWith` on a canonical path. Python
`tarfile.extractall` and `shutil.unpack_archive` without `filter=` are reported as
`zip-slip`.

`sast:config/*` reports unsafe Spring Boot settings in `application*.properties` and
`application*.yml`: every actuator endpoint exposed over HTTP, the H2 console enabled,
stack traces or exception messages returned to clients, TLS or CSRF switched off, and
debug or DevTools left on. Java's `getProperty("key", "default")` also reads these
files, so an algorithm named in a properties file is checked.

`sast:template/unescaped-output` (low) reports a template that prints a value without
HTML escaping: the `safe` filter in Jinja2, Django and Nunjucks, the `raw` filter in
Twig, `autoescape off`, EJS `<%-`, Handlebars triple braces, Mustache `&` tags, Blade `!!`
tags, ERB `<%==`, `raw` and `html_safe`, Pug `!=`, Vue `v-html`, Angular `[innerHTML]`, Razor `@Html.Raw`, Blazor `MarkupString`, and ASP.NET `<%= %>`.
It is a pattern, not
dataflow: a raw print of a string literal, an `inspect`ed value or a CSRF token is not
reported, anything else is. In PHP, a variable called `$html` or `$output` is treated as
a page buffer, so appending request data to it is reported as `xss`.

`sast:secrets/*` reports credentials in any text file, not only source: provider
tokens by their fixed shape (AWS, GitHub, GitLab, Slack, Stripe, Google, npm,
PyPI, SendGrid, OpenAI, Anthropic, Twilio, and private key blocks, rated
high), and `name = "literal"` for password, secret, token and key names in
code and configuration files when the literal looks random (rated medium).
Connection strings with a password (`Server=...;Password=...`) and URLs with credentials
(`postgres://user:secret@host/db`) are reported as well. The value is never copied into the report. Lockfiles, Markdown, minified files,
tests and documented example keys are skipped, and a literal that names another
variable (`var.db_password`) is not a secret.

React's `dangerouslySetInnerHTML` is an `xss` sink in `.jsx` and `.tsx`. Values
passed between components as props are not followed yet.

`sast` also checks infrastructure files for unsafe settings. These are
configuration checks, not dataflow, and have the rule ids `sast:iac/RULE`:

| Files                         | Rules                                                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Dockerfile`, `Containerfile` | `docker-root-user`, `docker-unpinned-image`, `docker-add-remote`, `docker-pipe-to-shell`, `hardcoded-secret`                                      |
| Kubernetes and Compose YAML   | `privileged-container`, `host-namespace`, `privilege-escalation`, `run-as-root`, `host-path-mount`, `docker-socket-mount`, `dangerous-capability` |
| Terraform (`.tf`, AWS)        | `open-ingress`, `public-bucket`, `public-database`, `unencrypted-storage`, `iam-wildcard`, `hardcoded-secret`                                     |
| `.github/workflows/*.yml`     | `actions-script-injection`, `actions-pwn-request`                                                                                                 |

Only the file itself is read: a Terraform module's inputs, Helm templates, and
Kustomize overlays are not rendered, so a setting supplied that way is not seen.
YAML is treated as a manifest only when it has `apiVersion` and `kind`, or a
`services` key. Remaining unsafe configuration, such as missing resource
limits, network policies or IAM least privilege beyond wildcards, is not
checked.

Sources are HTTP request data, command-line arguments and standard input: `net/http`, gin,
echo, fiber, chi and mux in Go; Express, Koa, Next.js, NestJS, Angular routes and the browser
URL in JavaScript; Flask, Django, FastAPI and Tornado in Python; servlets,
Spring and JAX-RS in Java; ASP.NET Core controller actions (`[FromQuery]`, `[FromBody]`, `Request.Query`)
and WebForms input controls (`txtName.Text`) in C#, with ASP.NET Core settings checked too (CORS with credentials for any origin, cookie `SecurePolicy`/`SameSite`, JWT audience/issuer validation off, certificate callbacks that always return true); the PHP superglobals and Laravel requests; Rails
and Sinatra `params`. Taint is tracked per field, through closures, interface
and inheritance calls, and across functions and files. A sanitizer clears only
the classes it neutralizes: HTML escaping stops `xss` but not SQL injection,
while an integer conversion or a digest clears everything. Test files,
`vendor`, `node_modules`, `testdata`, build output, and generated files are not
analyzed.

A file that does not parse is reported as `sast:analysis-incomplete`: its
vulnerabilities are unknown, not absent. A value that passes a strict check and
then leaves the function on failure (`if !allowed[x] { return }`, or an
anchored regular expression that admits only letters, digits and a few
separators) counts as validated. Channels, reflection, sessions and other
storage round trips, and field-level state of a method receiver are not
modeled, so a clean run is not proof of safety.

JavaScript functions are followed whether they are declared, assigned to a `const`, or
written in the older constructor style (`function Dao(db) { this.find = (x) => {...} }`
and `Dao.prototype.find = function (x) {...}`).

Go is type-checked, so callees are resolved exactly; for the other languages
callees are resolved through imports and declared types, and a call on a value
of unknown class is matched by method name only when at most three classes
define it. Calls into third-party libraries the rules do not name are assumed
to pass their arguments through to the result. `sast` uses the same `accept`,
`--exceptions`, and `--fail-on` flow as `audit`.

Go handlers that are registered in a table or callback map and never called directly have
no visible source, so `sast` does not follow their parameters by default. Pass
`--assume-params` to treat the string parameters of such functions as untrusted. It finds
those handlers (for example go-test-bench's), at the cost of more false positives on
library code whose callers validate their input.

### How accurate is sast

Accuracy is measured against the OWASP Benchmark, a labeled suite of small web handlers
that the analyzer was not written around. The score is the true-positive rate minus
the false-positive rate; a tool that guesses scores 0.

| Suite                       | True positives | False positives | Score |
| --------------------------- | -------------- | --------------- | ----- |
| BenchmarkJava 1.2 (2,740)   | 86%            | 15%             | +0.72 |
| BenchmarkPython 0.1 (1,230) | 80%            | 22%             | +0.59 |

The suites are not vendored. To reproduce, check one out and run
`SECUROCK_OWASP_BENCHMARK=/path/to/BenchmarkJava go test ./internal/sast -run OWASPBenchmark -v`
(or `SECUROCK_OWASP_BENCHMARK_PYTHON` for the Python suite). The test prints the rate for
each category and fails if the score drops.

Read the numbers with their limits in mind. Both suites are synthetic and contain
constructs real code rarely has: a switch on a constant string, a list whose first
element is removed before the second is read. The remaining false positives are mostly those. Algorithms read from a `.properties`
file with `getProperty("key", "default")` are resolved from the project's own properties
files. Juice Shop also ships each security challenge in several flawed and one correct variant
(`data/static/codefixes`), which makes a labeled set for JavaScript and TypeScript: the
vulnerable variants of the injection, XSS and redirect challenges are found, and the
parameterized SQL variants are not reported. Other languages have no labeled suite here, only the
cases in `internal/sast/testdata/bench.txt` and runs over intentionally vulnerable
applications (NodeGoat, Juice Shop, DVWA, railsgoat, WebGoat, pygoat), which were read
by hand. Treat the results as a measured starting point, not a guarantee.

`doctor` checks the setup around securock: the lockfile and policy,
registry config (`.npmrc`, `.yarnrc.yml`, `nuget.config`) for plain
http, disabled TLS and literal credentials, workflow actions that are
not pinned to a commit SHA, and missing repository rulesets.

`audit`, `sast` and `doctor` accept `--fail-on SEVERITY` (`critical`, `high`,
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
| `--lock`         | Path to `securock.lock` (for `lock` / `diff` / `update` / `verify`)                       |
| `--format`       | `text` (default), `json`, or `sarif`                                                      |
| `--output`       | Write the report to a file instead of stdout                                              |
| `--exceptions`   | Path to the accepted-findings file (`accept`, `audit`, `sast`, `doctor`)                  |
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
- `--format sarif` works on `scan`, `diff`, `verify`, `audit`, `sast`, and `doctor`.
  `sast` results point at the source line and carry a `codeFlows` trace.
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
`audit-report`, `sast-report`, `doctor-report`, `sbom-verify-report`).

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

- [Policy](/guide/policy) — default vs `strict`, custom YAML
- [Ecosystems](/guide/ecosystems) — which lockfiles and evidence depth
- [Evidence](/guide/evidence) — how to read evidence states
- [GitHub Action](/guide/action) — CI wiring
