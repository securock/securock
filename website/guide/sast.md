---
title: Source code analysis
description: "securock sast finds vulnerabilities in your own source code across 9 languages, fully offline — taint analysis, rule table, infrastructure checks, and accuracy."
---

# Source code analysis (`sast`)

`sast` analyzes the project's own source, offline, and reports untrusted
data that reaches a dangerous call along with the path it took. It
follows requests from HTTP handlers, command-line arguments, and
standard input through assignments, fields, closures, and calls into
SQL, command, code, path, NoSQL, request, response, and
deserialization sinks.

- **Languages**: Go, JavaScript and TypeScript (`js`), Python (`py`),
  Java (`java`), Kotlin (`kt`), C# (`cs`), PHP (`php`), and Ruby (`rb`).
- **Fully offline**: nothing is downloaded or executed.
- **Same triage flow**: `sast` uses the same
  [`accept`](/guide/reports#accept-findings), `--exceptions`, and
  `--fail-on` flow as `audit`.

```sh
securock sast [path]
securock sast --format json
securock sast --format sarif --output sast.sarif
```

`sast` results point at the source line and carry a `codeFlows` trace,
so SARIF uploads show the dataflow in GitHub code scanning. Rule ids
are `sast:LANGUAGE/RULE`:

## Rules

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

`sast:analysis-incomplete` (info) marks a file that could not be analyzed, including
analysis that exhausted its convergence budget.

## Third-party code in the tree

The packages a repository ships are analyzed too: an import of `vendor/`,
`node_modules/` or `site-packages/` is followed into the package's own code, so
a helper that ends in `cursor.execute` or `os.system` is reported at the call in
the project, and a helper that escapes or parameterizes its input is believed.
The package's own findings are not reported, and code that could not be read is
reported as `sast:analysis-incomplete` like any other file. Only the packages
the project imports are read, and nothing is downloaded: the analysis stays
offline.

## Rules that depend on what the data can be

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
`..`, or a prefix check on a cleaned/canonical path that includes the directory boundary
(`dest + path.sep`, `dest.getCanonicalPath() + File.separator`). A bare prefix is
insufficient: `/safe-other` starts with `/safe`. These path checks do not neutralize SQL
injection or XSS. Python
`tarfile.extractall` and `shutil.unpack_archive` without `filter=` are reported as
`zip-slip`.

## Configuration and infrastructure checks

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

## Taint tracking

Sources are HTTP request data, command-line arguments and standard input: `net/http`, gin,
echo, fiber, chi and mux in Go; Express, Koa, Next.js, NestJS, Angular routes and the browser
URL in JavaScript; Flask, Django, FastAPI and Tornado in Python; servlets,
Spring and JAX-RS in Java; ASP.NET Core controller actions (`[FromQuery]`, `[FromBody]`, `Request.Query`)
and WebForms input controls (`txtName.Text`) in C#, with ASP.NET Core settings checked too (CORS with credentials for any origin, cookie `SecurePolicy`/`SameSite`, JWT audience/issuer validation off, certificate callbacks that always return true); the PHP superglobals and Laravel requests; Rails
and Sinatra `params`. Taint is tracked per field, through closures, interface
and inheritance calls, and across functions and files. Function summaries preserve
parameter/receiver field dependencies and writes through reference arguments, so
`request → setter → field → getter → SQL` is followed without treating an unrelated
field on the same object as part of the query. Constructors and returned Go structs,
JavaScript objects and Python dictionaries preserve their modeled fields too.
A sanitizer clears only
the classes it neutralizes: HTML escaping stops `xss` but not SQL injection,
while an integer conversion or a digest clears everything. Test files,
`vendor`, `node_modules`, `testdata`, build output, and generated files are not
analyzed.

A file that does not parse is reported as `sast:analysis-incomplete`: its
vulnerabilities are unknown, not absent. A value that passes a strict check and
then leaves the function on failure (`if !allowed[x] { return }`, or an
anchored regular expression that admits only letters, digits and a few
separators) counts as validated for the classes that check prevents. Assignments,
including writes through a modeled alias, invalidate affected validation facts.
Request-controlled collections are not trusted as allowlists.

The analyzer follows direct local reference aliases (Go pointers/maps/slices and
objects in the other languages), and distinguishes them from Go struct value copies.
Aliases that are only possible on some branches and writes summarized across calls
are updated conservatively: these can retain taint and report a safe overwrite.
Reference identity returned by helpers, aliases to nested subobjects, reflection,
channels, sessions and other storage round trips are not fully modeled, so a clean
run is not proof of safety.

Call summaries are reanalyzed when their dependencies change, rather than stopping
after a fixed number of whole-project passes. Loop-carried taint is propagated to a
fixed point, with `break` kept separate from `continue`. Computation is bounded:
loops allow 128 propagation rounds, and function analyses share a project-sized
work budget (at most 1,000,000 evaluations). Exhaustion produces
`sast:analysis-incomplete`, retaining the findings already obtained. Field paths
deeper than eight segments are conservatively merged into the enclosing object,
which can increase false positives.

JavaScript functions are followed whether they are declared, assigned to a `const`, or
written in the older constructor style (`function Dao(db) { this.find = (x) => {...} }`
and `Dao.prototype.find = function (x) {...}`).

Go is type-checked, so callees are resolved exactly; for the other languages
callees are resolved through imports and declared types, and a call on a value
of unknown class is matched by method name only when at most three classes
define it. Calls into third-party libraries the rules do not name are assumed
to pass their arguments through to the result.

Go handlers that are registered in a table or callback map and never called directly have
no visible source, so `sast` does not follow their parameters by default. Pass
`--assume-params` to treat the string parameters of such functions as untrusted. It finds
those handlers (for example go-test-bench's), at the cost of more false positives on
library code whose callers validate their input.

## How accurate is sast

Accuracy is measured against the OWASP Benchmark, a labeled suite of small web handlers.
These are development and regression benchmarks: failures in these suites inform fixes,
so they are not an independent, held-out evaluation. The table records the last published
measurements; it is not a new measurement of every subsequent dataflow change.
The score is the true-positive rate minus
the false-positive rate; a tool that guesses scores 0.

| Suite                       | True positives | False positives | Score   |
| --------------------------- | -------------- | --------------- | ------- |
| BenchmarkJava 1.2 (2,740)   | 99.7%          | 1.0%            | +0.9874 |
| BenchmarkPython 0.1 (1,230) | 98.9%          | 1.0%            | +0.9787 |

The suites are not vendored. To reproduce, check one out and run
`SECUROCK_OWASP_BENCHMARK=/path/to/BenchmarkJava go test ./internal/sast -run OWASPBenchmark -count=1 -v`
(or `SECUROCK_OWASP_BENCHMARK_PYTHON` for the Python suite). The test prints the rate for
each category and guards true positives and false positives separately in each category.
Missing cases, unmapped categories and incomplete analysis also fail the test. Set
`SECUROCK_BENCHMARK_DETAILS=1` to list misclassified cases. CI uses pinned suite revisions.
Each suite also rejects aggregate FPR above 2%, using exact counts. This aggregate
ceiling does not imply that every individual category has FPR below 2%.
See [SAST benchmarks](/reference/sast-benchmarks) for revisions, exact counts and reproduction.

Python now includes the suite's imported helpers in the analysis root; earlier measurements
scanned only `testcode`. The benchmark reference separates that measurement correction from
the engine improvements.

PyGoat also has a reproducible application regression test, using a pinned revision
and manually reviewed cases from nine independent Python labs. It detects **all 14
selected vulnerable cases**, with neither of two safe controls flagged
for its labeled rule and zero incomplete-analysis findings. This small
selection is not an application-wide accuracy or false-positive-rate estimate.
Run it with
`SECUROCK_PYGOAT=/path/to/pygoat go test ./internal/sast -run '^TestPyGoat$' -count=1 -v`.
See [PyGoat application regression](/reference/sast-benchmarks#pygoat-application-regression)
for the exact revision, labels, category counts and full reproduction steps.

Pinned source regressions also cover **JavaScript, TypeScript and PHP**:

| Language   | Source selection                                        | Vulnerable cases detected | Safe controls flagged | Analysis incomplete |
| ---------- | ------------------------------------------------------- | ------------------------: | --------------------: | ------------------: |
| JavaScript | NodeGoat handlers and DAOs                              |                       4/4 |                   0/1 |                   0 |
| TypeScript | Juice Shop search route and SQL/NoSQL code-fix variants |                       4/4 |                   0/4 |                   0 |
| PHP        | DVWA SQL, command and redirect source variants          |                       8/8 |                   0/3 |                   0 |

The NodeGoat finding now points at the MongoDB database call; before the change
the same flow was reported only at the nested `$where` builder. Juice Shop's two
false positives, an unreachable SQL query and a string-validated NoSQL selector,
are cleared. DVWA adds a reviewed case where quote escaping is used unquoted, so
the denominator changed. No selected case is currently a known miss or known false
positive, but these are small, manually reviewed source/rule cases, not
full-application or language-wide accuracy measurements; the OWASP 2% FPR ceiling
does not apply. No application or dependency is installed or executed. CI checks
the pinned sources and guards individual detections and safe controls.
See [JS, TS and PHP source regressions](/reference/sast-benchmarks#javascript-typescript-and-php-source-regressions)
for revisions, all labels, counts and reproduction commands using
`SECUROCK_NODEGOAT`, `SECUROCK_JUICE_SHOP` and `SECUROCK_DVWA`.

Read the numbers with their limits in mind. The two OWASP suites are synthetic and contain
constructs real code rarely has. Constant Java `switch` and Python `match` selectors, and
Python arithmetic and conditional expressions, are now evaluated when their values are known.
Java switch fallthrough is preserved; unknown patterns and guards keep all alternatives.
Escaped strings and formatting that are not fully decoded stay unknown for constant folding.
Local Python lists and Java ArrayList/LinkedList instances track up to 64 elements separately,
including insertions and indexed removals. Aliases, unknown mutations, escaping calls and
larger lists fall back to conservative whole-list taint.

Python XPath checks include `elementpath.select`, `iter_select` and `Selector`.
A quote-removal operation or a rejecting quote check only protects input embedded inside
the matching XPath string literal. The same input used as a raw XPath expression, inside
the opposite quote style, or in SQL remains untrusted. Unknown transformations discard
the local XPath-context safety fact.

Python `ConfigParser` round trips are tracked per section and key; `get()` of a
known-safe key stays safe, while unknown keys and `read_dict` remain conservative.
Python `subprocess` argument vectors are checked for explicit command modes
(`sh -c`, `cmd.exe /c`, PowerShell `-Command`) even without `shell=True`. Java
session keys and values are both checked, and `Random.nextBytes` follows the
buffer it writes. A Python `make_response((body, headers))` checks only the body,
and rejecting `..` validates only the path class. Python text buffers are
followed through `write()` and `getvalue()` (for example `io.StringIO`).

Python recognizes a complete quoted-string guard before direct `eval` and `exec`
calls: matching opening and closing quotes, with no matching quote in the
`[1:-1]` interior. This does not validate template code, SQL or shell input.
An exact literal `netloc` allowlist plus an HTTP/HTTPS scheme check on a
`urllib.parse.urlparse` or `urlsplit` result validates the original URL for a
direct redirect. Reassignment invalidates that relationship, and unknown
transformations remain untrusted. Validation inside `try` survives only when
all exception handlers terminate and there is no `else` or `finally` clause.

Static Flask route-path splits now have fixed components when application ownership
and the handler's route constraint are known. Unknown routers, blueprints, conflicting
or dynamic routes and escaping handlers remain conservative. Registration functions
can establish ownership through direct project calls or `importlib` module calls;
unknown or conflicting callers discard it. Reassignments and list mutations still
invalidate the relevant facts. Writes to or escape of the request object, including
writes through project helpers, discard the route-path proof.

Python also recognizes an always-rejecting comparison between an absolute resolved
path and a known relative basename. This prunes unreachable file operations rather
than trusting boundary-less prefix checks. Drive-relative and one-letter prefixes
stay unknown for cross-platform correctness, and writes to imported constants
invalidate constant-path proofs.

Remaining errors include more complex collections, library models and validation
patterns. Python retains five path-traversal misses, one XSS false positive from a
project-specific escaper, and seven XXE false positives from parser configuration
checks that do not inspect the parsed input. The XXE category has only 20 safe cases,
so its category-specific FPR remains high despite the low aggregate rate.

Only Java and Python have an OWASP Benchmark score. For the other languages the evidence is weaker,
and `sast` should be treated as experimental there:

| Language              | What it was checked against                                                                                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Java                  | OWASP BenchmarkJava (score above), WebGoat                                                                                                                                                             |
| Python                | OWASP BenchmarkPython (score above), PyGoat (14 selected vulnerable cases and two safe controls; results above), django.nV                                                                             |
| JavaScript/TypeScript | Pinned NodeGoat and Juice Shop SQL/NoSQL source regressions (results above); exploratory checks against other Juice Shop `codefixes`, njsscan true negatives and dvna are not included in those counts |
| Go                    | gosec's samples (SQL injection, TLS and RSA key size covered; rules that need no tainted data are only partly matched), go-test-bench with `--assume-params`                                           |
| PHP                   | Pinned DVWA SQL, command and redirect source regressions (results above); no comparable benchmark score                                                                                                |
| Ruby, C#, Kotlin      | Intentionally vulnerable applications read by hand (railsgoat, WebGoat.NET, ktor-samples, spring-petclinic-kotlin) and repository unit tests; no labeled score                                         |

Known limits:

- Rules that fire without tainted data (hard-coded keys, weak algorithms, insecure flags) match
  the API calls the tables list. An API the tables do not name is not reported.
- A value that reaches a sink only through a library the rules do not model is assumed to pass
  through, which can add false positives.
- A file the grammar cannot parse is reported as `sast:analysis-incomplete` and not analyzed.
  Kotlin has the most such files because its grammar rejects some constructs, which `sast`
  rewrites around where it can.
- `#nosec`-style comments are not read. Use `accept` and the [exceptions file](/guide/reports#accept-findings).

Treat the results as a measured starting point, not a guarantee.

## Next steps

- [SAST benchmarks](/reference/sast-benchmarks) — revisions, exact counts, reproduction
- [Triage and exports](/guide/reports) — suppress a finding with a reason
- [Usage](/guide/usage) — flags shared with the other commands
