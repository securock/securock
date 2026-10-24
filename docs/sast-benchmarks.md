# SAST benchmarks

OWASP Benchmark and selected PyGoat, NodeGoat, Juice Shop and DVWA source cases
are development and regression suites for Securock's SAST. Their labeled failures inform parser,
dataflow and library-model improvements. They are **not a held-out evaluation**,
and these scores do not establish parity
with another scanner or predict accuracy on an arbitrary application.

## Revisions and method

| Input | Revision |
| --- | --- |
| Securock before this improvement | `60cd4f3a9713e8c4c9bc2ca78b86d2f68dc072bd` |
| Securock before Python guard precision | `cd05878e471491519eaf2256f9bb6046cbfac00d` |
| OWASP BenchmarkJava 1.2 | `acc50f20ec449e2b977a7c409fa8175491657cba` |
| OWASP BenchmarkPython 0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |

The improved results below use the changes introducing this reference. Measurements
ran with Go 1.27.1 on darwin/arm64, with the test cache disabled. Java scans
`src/main`; Python scans the suite root, including imported helpers. The suites
are read as source; their applications are not executed.

Each labeled handler is scored for its expected vulnerability category. A matching
rule in that handler is a hit. Other rule categories and findings outside labeled
handlers are not included in the confusion matrix. All 2,740 Java and 1,230 Python
labels remain in the denominator, including any handler that cannot be analyzed.
Both measured runs produced zero `analysis-incomplete` findings.

- True-positive rate (TPR): TP / (TP + FN), the proportion of vulnerable cases found.
- False-positive rate (FPR): FP / (FP + TN), the proportion of safe cases flagged.
- Score: TPR minus FPR, aggregated over cases rather than averaged over categories.

FPR is not the proportion of reported alerts that are false. The synthetic ratio
of vulnerable to safe cases also differs from a typical production repository.

## Before and after

| Measurement | TP | FN | FP | TN | TPR | FPR | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Java, before | 1,291 | 124 | 193 | 1,132 | 91.24% | 14.57% | +0.7667 |
| Java, first improvement | 1,364 | 51 | 126 | 1,199 | 96.40% | 9.51% | +0.8689 |
| Java, after collection/XPath work | 1,364 | 51 | 13 | 1,312 | 96.40% | 0.98% | +0.9541 |
| Java, current | 1,411 | 4 | 13 | 1,312 | 99.72% | 0.98% | +0.9874 |
| Python, old `testcode`-only scope | 363 | 89 | 183 | 595 | 80.31% | 23.52% | +0.5679 |
| Python, before, corrected scope | 389 | 63 | 202 | 576 | 86.06% | 25.96% | +0.6010 |
| Python, first improvement, corrected scope | 395 | 57 | 131 | 647 | 87.39% | 16.84% | +0.7055 |
| Python, after collection/XPath work | 405 | 47 | 87 | 691 | 89.60% | 11.18% | +0.7842 |
| Python, after dataflow/library work | 447 | 5 | 66 | 712 | 98.89% | 8.48% | +0.9041 |
| Python, after guard precision | 447 | 5 | 46 | 732 | 98.89% | 5.91% | +0.9298 |
| Python, current, corrected scope | 447 | 5 | 8 | 770 | 98.89% | 1.03% | +0.9787 |

On identical analysis scopes, the first improvement gained 73 true positives and
removed 67 false positives in Java; Python gained 6 true positives and removed 71
false positives. The collection/XPath work removed another 113 Java false positives
without losing detections, and gained 10 Python true positives while removing 44
false positives. The dataflow/library round adds 47 Java detections with no new false
positives, and 42 Python detections while removing 21 false positives. The
additional change from Python's old scope is a measurement correction, not an
engine improvement.

The Python guard-precision round removes another 20 false positives (12 code
injection and 8 redirect), reducing the false-positive count by 30.3% without
losing a detection in any category. Java's counts remain unchanged. Both suites
still produce zero `analysis-incomplete` findings.

Route/path precision removes another 38 Python false positives while preserving
all 447 true positives, bringing aggregate FPR below the 2% regression ceiling.
This ceiling applies to each suite's aggregate FPR, not to every category:
Python's remaining seven XXE false positives are among only 20 safe XXE cases.

The improvements preserve Python comparison operators and chained comparisons,
evaluate known arithmetic and conditional expressions, isolate constant facts
between alternative branches, and select known Java switch / Python match arms.
Unknown operations, patterns, guards, overflowing tracked Python integers and
undecoded strings remain conservative. Library models add typed Java LDAP search,
Java file metadata operations and Python pathlib metadata operations, including
paths composed with `/` and `joinpath`.

The second round tracks positions in fresh local Python lists and Java
ArrayList/LinkedList instances, including insertion and removal shifts. Exact
tracking is limited to 64 elements. Unknown indices/mutations, aliases and escaping
calls retain whole-list taint rather than assuming an element is safe. Nested
mutable lists that escape together are conservatively linked; this is not a full
heap or alias analysis.

Python XPath models now include `elementpath.select`, `iter_select` and `Selector`.
Literal text around concatenations and f-string substitutions is retained, including
supported Python escapes. A value known not to contain a particular quote can be
confined to an XPath literal using that quote. This does not sanitize raw expressions,
the opposite quote context or other vulnerability classes. Reassignment invalidates
validation facts; unknown transformations and calls across function boundaries
discard the local query-context safety fact. Unsupported formatting, XPath comments
and URI-qualified names are handled conservatively.

The dataflow/library round adds:
- Python `ConfigParser` round trips with section/key precision, so `get()` of a
  known-safe key stays safe while the value stored under an untrusted key remains
  tainted. Unknown keys and `read_dict` stay conservative.
- Explicit shell detection for Python `subprocess` argument vectors: `sh -c`,
  `cmd.exe /c` and PowerShell `-Command` are modeled even without `shell=True`,
  while ordinary argv lists and non-command-mode options are not reported.
- Java session keys as well as values (`setAttribute` and `putValue`).
- Java `Random.nextBytes`/`RandomGenerator.nextBytes` effects on their output
  buffer, so a `SecureRandom` instance typed as `Random` is not called weak.
- Python `make_response((body, headers))`: only the body is an HTML sink.
- Rejecting `..` in Python is recognized as a path-only validation, not as
  protection for SQL or other classes.
- Python text buffers are followed through `write()` and `getvalue()`, covering
  `io.StringIO` query construction without treating the buffer as trusted.

These models remain conservative: unknown keys, aliases, escaping calls and
unsupported formatting keep the original taint. They do not infer from function
names or silence a class the check does not neutralize.

The Python guard-precision round recognizes two complete validations:
- A value that starts and ends with the same single or double quote, with no
  matching quote in its `[1:-1]` interior, is a plain Python string literal or
  invalid syntax. This protects direct `eval` and `exec` calls only; template,
  SQL and shell sinks still treat it as untrusted.
- A `urllib.parse.urlparse` or `urlsplit` result with an exact literal `netloc`
  allowlist and an HTTP/HTTPS scheme check validates the original URL for a direct
  redirect. Parsing alone, host-prefix checks and request-controlled allowlists
  do not validate it. The relationship is invalidated on reassignment, and an
  unknown transformation of a validated URL remains untrusted.

Validation in a Python `try` body survives when every exception handler returns
or raises and there is no `else` or `finally` clause. A handler that can continue
keeps the unvalidated alternative.

The route/path round adds two narrow proofs:
- Splitting Flask `request.path` on `/` yields fixed components when the handler
  has a known static route on a known Flask application. Router ownership is
  followed through project registration functions and `importlib` module calls.
  Unknown or conflicting callers, blueprints, dynamic or conflicting routes,
  escaping handler references and direct calls without the same route constraint
  discard the proof. Writes to or escape of the request object, including writes
  through project helpers, also discard it. Query input and unsupported path
  transformations stay tainted;
  mutation and escape of a split list retain the normal conservative list model.
- A resolved absolute pathlib path cannot start with a known relative basename
  such as `assets`. A rejecting check using that comparison always exits, so the
  file operation after it is unreachable. This is not a containment sanitizer:
  absolute directory prefixes without a separator boundary still report traversal.
  One-letter and drive-relative prefixes remain unknown because Windows absolute
  paths can begin with a drive letter. Reassignment, branch disagreement and writes
  to imported constants invalidate these facts.

Project-specific HTML encoders and parser-input-sensitive XXE configuration
checks remain gaps.

## Remaining weak categories

| Suite / category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| Java trust boundary | 79 | 4 | 0 | 43 |
| Java weak random | 218 | 0 | 0 | 275 |
| Python path traversal | 60 | 5 | 0 | 103 |
| Python SQL injection | 5 | 0 | 0 | 11 |
| Python XSS | 31 | 0 | 1 | 57 |
| Python XXE | 8 | 0 | 7 | 13 |

The Python SQL category has only five vulnerable cases. High aggregate results
must not conceal weak individual categories or missing real-world framework
coverage. The selected JavaScript, TypeScript and PHP regressions below are not
comparable labeled benchmarks. Independent real-application evaluation remains
necessary before making broader accuracy claims.

## Reproduce

### OWASP Benchmark

Run from the Securock repository root, using external directories for the suites:

```sh
git clone https://github.com/OWASP-Benchmark/BenchmarkJava /tmp/securock-benchmark-java
git -C /tmp/securock-benchmark-java checkout acc50f20ec449e2b977a7c409fa8175491657cba
git clone https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/securock-benchmark-python
git -C /tmp/securock-benchmark-python checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba

SECUROCK_OWASP_BENCHMARK=/tmp/securock-benchmark-java \
SECUROCK_OWASP_BENCHMARK_PYTHON=/tmp/securock-benchmark-python \
SECUROCK_BENCHMARK_DETAILS=1 \
go test ./internal/sast -run '^TestOWASPBenchmark' -count=1 -v -timeout 15m
```

The test prints category counts, rates, incomplete-analysis counts and, with
`SECUROCK_BENCHMARK_DETAILS`, the names of false-positive and false-negative cases.
It guards minimum true positives and maximum false positives **separately for each
category**. Missing source cases, invalid or duplicate labels, unmapped categories,
unexpected suite sizes and incomplete analysis fail the test too. Improvements in
one category cannot compensate for a regression in another.

Both suites also enforce an aggregate FPR of **2% or less**, using exact integer
counts rather than rounded percentages. Python has 778 safe cases, so 15 false
positives pass that ceiling and 16 fail. Unit tests cover that boundary and reject
an evaluation with no safe cases. The current per-category FP limits are tighter
still: their Python maxima total eight, and the TP minimums remain unchanged.

`.github/workflows/sast-benchmark.yml` uses the pinned revisions on relevant pull
requests, main-branch pushes, a weekly schedule and manual dispatch. Normal
`go test ./...` skips the external suites unless their environment variables are
set. Updating a suite revision requires reviewing the changed labels and counts,
then updating the documented measurements and regression limits together.

## PyGoat application regression

[PyGoat](https://github.com/adeyosemanputra/pygoat) is an intentionally vulnerable
application, not an upstream labeled benchmark. The regression test uses manually
reviewed cases from **nine independent Python labs** in `dockerized_labs`, with
14 vulnerable cases and two category-specific safe controls. It does not score
every challenge, every finding, or the Django application that manages the labs.
Authentication, authorization, business logic and dependency vulnerabilities are
outside this selection.

| Input | Revision |
| --- | --- |
| PyGoat | `46fef968f3f44d1191363baf936aaa3335dc5c6d` |
| Securock analyzer used for this measurement | `a5b66a55525dc0253a43f7af45bfa549ad6d5ca8` |

The measurement uses that analyzer with the added `TestPyGoat` harness, Go 1.27.1
on darwin/arm64 and the test cache disabled. Each lab is scanned separately as a
complete source directory, so unrelated `app.py` modules and same-named handlers
are not combined into one project. No application, container or Python dependency
is installed or executed.

### Results

| Category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| SQL injection | 1 | 0 | 0 | 1 |
| Command injection | 1 | 0 | 0 | 0 |
| Code/template injection | 1 | 1 | 0 | 0 |
| Path traversal | 1 | 0 | 0 | 0 |
| SSRF | 1 | 0 | 0 | 0 |
| Insecure deserialization | 2 | 0 | 0 | 1 |
| Weak crypto | 2 | 0 | 0 | 0 |
| XSS | 0 | 3 | 0 | 0 |
| XXE | 1 | 0 | 0 | 0 |
| **Total** | **10** | **4** | **0** | **2** |

Securock detects **10 of 14 selected vulnerable cases (71.43%)**. Neither safe
control is flagged for its labeled rule, and all nine scans produce zero
`analysis-incomplete` findings. Two controls are too few to support a meaningful
application-wide false-positive-rate or TPR-minus-FPR score. The 2% FPR ceiling
for OWASP Benchmark does not apply to this selection.

### Reviewed labels

Paths below are relative to `dockerized_labs`. A case is a function/rule pair:
only a finding for the expected rule within that function counts as a hit.
Other rule categories and findings outside the selected functions are not scored.
For SHA-1, the case is the `custom_hash` helper where the weak API is called,
rather than counting its caller again.

| Source / function | Expected category | Result | Label rationale |
| --- | --- | --- | --- |
| `sql_injection_lab/app.py:lab` | SQL injection | TP | Request fields interpolated into the query passed to `execute`. |
| `sql_injection_lab/app.py:init_db` | SQL injection | TN | Fixed schema statements and a parameterized insert. This control has no request input. |
| `command_injection_lab/app.py:lab1` | Command injection | TP | Request domain interpolated into `Popen` with `shell=True`. |
| `command_injection_lab/app.py:lab2` | Code injection | TP | Request expression passed to `eval`. |
| `ssrf_lab/app.py:lab1` | Path traversal | TP | Request filename joined to a base path and passed to `open` without containment validation. This is a file-access case despite the lab's SSRF name. |
| `ssrf_lab/app.py:lab2` | SSRF | TP | Request URL passed directly to `requests.get`. |
| `insec_des_lab/main.py:deserialize_data` | Insecure deserialization | TP | Base64-decoded request data passed to `pickle.loads`. |
| `insec_des_lab/main.py:serialize_data` | Insecure deserialization | TN | Request data is serialized with `pickle.dumps`, not deserialized. |
| `software_integrity_lab/app.py:lab1` | Insecure deserialization | TP | Base64-decoded request cookie passed to `pickle.loads`. |
| `crypto_failure_lab/app.py:lab1` | Weak crypto | TP | MD5 used for password verification. |
| `crypto_failure_lab/app.py:custom_hash` | Weak crypto | TP | SHA-1 used by the password-verification helper. |
| `xxe_lab/app.py:xxe_parse` | XXE | TP | External general entities explicitly enabled on the parser used for request XML. The hit is at `setFeature`, not proof of parser-input-sensitive flow analysis. |
| `xss_lab/app.py:lab1` | XSS | FN | Request query rendered through the `safe` filter in `templates/lab1.html`. |
| `xss_lab/app.py:lab2` | XSS | FN | Removing literal script tags does not neutralize other HTML; `templates/lab2.html` uses the `safe` filter on `username`. |
| `xss_lab/app.py:lab3` | XSS | FN | Removing alphanumeric characters still permits JavaScript expressions; `templates/lab3.html` inserts the result as script code. |
| `template_injection_lab/app.py:view_blog` | Code/template injection | FN | `create_blog_post` interpolates request title/content into a template file; `view_blog` later renders it as Jinja source. |

The remaining four misses need template-context modeling and tracking through
stored template files. The source comment in `software_integrity_lab:lab2`
describes XSS, but that is not by itself a vulnerability label; that handler is
not included in the scored XSS cases.

### Reproduce PyGoat

Run from the Securock repository root:

```sh
git clone https://github.com/adeyosemanputra/pygoat /tmp/securock-pygoat
git -C /tmp/securock-pygoat checkout 46fef968f3f44d1191363baf936aaa3335dc5c6d

SECUROCK_PYGOAT=/tmp/securock-pygoat \
go test ./internal/sast -run '^TestPyGoat$' -count=1 -v -timeout 5m
```

The test always prints each case's outcome, category counts and incomplete-analysis
count. It guards every currently detected vulnerable case individually, rejects a
false positive on either safe control and fails on incomplete analysis. Known
misses stay in the denominator; detecting one is allowed and should prompt an
update to the required detections and this result table.

SHA-256 checks pin all nine labeled Python files and the three XSS templates;
missing or changed inputs fail before scoring. Updating the PyGoat revision
requires reviewing the labels, checksums, measurements and required detections
together. Function-boundary unit tests run without an external checkout and
prevent a neighboring handler's finding from satisfying another case.

The same SAST benchmark workflow fetches the pinned PyGoat revision and runs
`TestPyGoat` alongside the two OWASP suites. Normal `go test ./...` skips the
external PyGoat scan unless `SECUROCK_PYGOAT` is set.

## JavaScript, TypeScript and PHP source regressions

`TestNodeGoat`, `TestJuiceShop` and `TestDVWA` in
`internal/sast/application_benchmarks_test.go` add manually reviewed source/rule
cases from intentionally vulnerable applications. These are **selected source
regressions**, not upstream labeled benchmarks, full-application assessments or
held-out evaluations. Labels describe the selected vulnerability category only:
a safe control can have unrelated vulnerabilities or broken functionality.

### Revisions and scope

| Input | Revision |
| --- | --- |
| [NodeGoat](https://github.com/OWASP/NodeGoat) (JavaScript) | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` |
| [Juice Shop](https://github.com/juice-shop/juice-shop) (TypeScript) | `717f5efa886b0417eeecb52378b03cf10567b7e2` |
| [DVWA](https://github.com/digininja/DVWA) (PHP) | `a1978a2fed195acd093010af6395f86a281537ca` |
| Securock analyzer before these fixes | `45f37f8efbd2ed395cf115578aa425e44e6c246c` |
| Securock analyzer after these fixes | `4661cbfc2ff2dc6b9ddffdd7e6dcec78d8e2a53c` |

Measurements use those analyzer revisions with the added test harness, Go
1.27.1 on darwin/arm64 and the test cache disabled. Only explicitly listed,
SHA-256-pinned inputs are copied byte-for-byte to temporary analysis roots; no
application, container, JS/TS/PHP runtime or application dependency is
installed or executed.

- **NodeGoat:** all 17 JavaScript files directly in `app/routes` and `app/data`,
  plus `config/config.js`, analyzed together with their original relative paths.
  This retains project-local handler/DAO calls. Templates, assets, the application
  entrypoint and environment-specific configuration are outside this source selection.
- **Juice Shop:** `routes/search.ts` and six standalone SQL/NoSQL `codefixes`
  fragments, each analyzed separately. This avoids conflating mutually exclusive
  variants with the same exported names. Imported application modules and packages
  are not copied; unresolved calls use the analyzer's normal conservative models.
  TypeScript findings use the shared `sast:js/*` rule ids.
- **DVWA:** eleven `source/*.php` files, each analyzed separately because the security
  levels are mutually exclusive and reuse globals. The selection covers two SQL
  injection cases, four command injection cases and four open redirect cases, not
  the surrounding page-rendering flow or other DVWA challenges.

The labels were selected by reading the source before scanning, rather than
keeping only cases the analyzer detects. A hit requires the expected rule in the
exact file and inclusive line range below. Multiple sinks in one labeled range
count as **one case**, not one case per sink; findings in other ranges or rule
categories are not scored. Missing/changed inputs, invalid/overlapping labels and
any `analysis-incomplete` finding fail the test. Unit tests verify checksum and
label validation, variant isolation, and that a neighboring handler, another file
or another rule cannot satisfy a label.

### Results

| Suite / language | TP | FN | FP | TN | Vulnerable cases detected | Safe controls flagged | Analysis incomplete |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| NodeGoat / JavaScript | 4 | 0 | 0 | 1 | 4/4 | 0/1 | 0 |
| Juice Shop / TypeScript | 4 | 0 | 0 | 4 | 4/4 | 0/4 | 0 |
| DVWA / PHP | 8 | 0 | 0 | 3 | 8/8 | 0/3 | 0 |

| Suite | Before (TP/FN/FP/TN) | After (TP/FN/FP/TN) | Change |
| --- | --- | --- | --- |
| NodeGoat / JavaScript | 3/1/0/1 | 4/0/0/1 | The database-use location is now reported. |
| Juice Shop / TypeScript | 4/0/2/2 | 4/0/0/4 | Both known false positives are cleared. |
| DVWA / PHP | 7/0/0/3 | 8/0/0/3 | One reviewed case was added and detected. |

The DVWA denominator changed between the two measurements, so its totals are
not a before/after score comparison. The NodeGoat baseline already reported the
same request flow at the `$where` construction on line 78, but the selected
database-use case on line 86 was a miss. The new finding is at the `find` call;
this is a more actionable location, not a newly discovered vulnerability, and
the original label is unchanged.

| Suite / category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| NodeGoat code injection | 1 | 0 | 0 | 0 |
| NodeGoat NoSQL injection | 1 | 0 | 0 | 0 |
| NodeGoat SSRF | 1 | 0 | 0 | 0 |
| NodeGoat open redirect | 1 | 0 | 0 | 1 |
| Juice Shop SQL injection | 2 | 0 | 0 | 3 |
| Juice Shop NoSQL injection | 2 | 0 | 0 | 1 |
| DVWA SQL injection | 2 | 0 | 0 | 1 |
| DVWA command injection | 3 | 0 | 0 | 1 |
| DVWA open redirect | 3 | 0 | 0 | 1 |

The JavaScript changes follow the query object returned by a local builder to
the database call, keep `String()` from hiding a `$where` payload, and recognize
that contradictory literal prefixes make a branch unreachable. A terminating
`typeof value === 'string'` check clears object-operator injection only for the
value it directly checks; it does not sanitize SQL, shell or JavaScript text,
and it does not vouch for a different value that was merely stringified. The
same distinction applies to bracket access and local variables, while unknown
guards, non-terminating checks and unsafe alternatives stay tainted.

For PHP, quote escaping is now a local fact consumed only at a SQL sink. A value
returned by `mysqli_real_escape_string`, `mysql_real_escape_string`,
`pg_escape_string` or `mysqli::real_escape_string` is protected only while it
occupies a quoted SQL string literal. Using it unquoted, as an identifier, after
reassignment, in only one branch or after an unknown transformation remains a
finding. Integer conversion and prepared statements stay safe. Comments,
backticks and undecoded escapes stay conservative rather than assuming a SQL
dialect.

There are only one, four and three safe controls respectively. These counts do
not support a language-wide or application-wide accuracy/FPR claim, nor a score
comparable to OWASP Benchmark. Its 2% aggregate FPR ceiling does not apply here.
No selected case is currently a known miss or known false positive, but that
does not make JS/TS/PHP analysis complete. Support remains experimental beyond
this narrow evidence.

### Reviewed NodeGoat labels

Paths are relative to the NodeGoat checkout. Each row is one source/rule case.

| Source / lines | Category | Result | Label rationale |
| --- | --- | --- | --- |
| `app/routes/contributions.js:32-34` | Code injection | TP | Three request body values passed to `eval` before validation. |
| `app/data/allocations-dao.js:86` | NoSQL injection | TP | `allocations.js` passes request `threshold` to the DAO; the nested `searchCriteria` interpolates it into `$where` without escaping. The finding is at the database call, not only at the query object's construction on line 78. |
| `app/routes/research.js:16` | SSRF | TP | `needle.get` receives the concatenated request URL and symbol without destination validation. |
| `app/routes/index.js:72` | Open redirect | TP | `/learn` redirects directly to `req.query.url`. |
| `app/routes/session.js:36-42` | Open redirect | TN | Login middleware redirects to a fixed `/login` path, not a request-controlled destination. |

### Reviewed Juice Shop labels

Except for the first two rows, paths are relative to `data/static/codefixes`.
Upstream `_correct` names are not used as vulnerability labels without source
review. In particular, the SQL variant numbered 3 always rejects ordinary string
input: no string starts with **both** `apple` and `orange`, so the `||` of their
negated checks returns before the query. This prevents this SQL injection by
making the handler unusable, not by correctly sanitizing input. Non-string query
values fail at the string operations before reaching the query.

| Source / lines | Category | Result | Label rationale |
| --- | --- | --- | --- |
| `routes/search.ts:23` | SQL injection | TP | Request search text interpolated into a raw SQL query. |
| `routes/search.ts:47` | SQL injection | TN | Fixed `SELECT sql FROM sqlite_master` statement with no request interpolation. |
| `unionSqlInjectionChallenge_1.ts:6` | SQL injection | TP | `replace` discards its return value, leaving request text interpolated into SQL. |
| `unionSqlInjectionChallenge_2_correct.ts:5-8` | SQL injection | TN | SQL text is fixed and criteria is passed separately as replacements, not interpolated. This label does not establish correct search behavior. |
| `unionSqlInjectionChallenge_3.ts:10` | SQL injection | TN | Query is unreachable after the always-rejecting prefix check described above. |
| `noSqlReviewsChallenge_1.ts:10-13` | NoSQL injection | TP | Rejecting only `$ne` still allows other query operators such as `$gt` in request `id`. |
| `noSqlReviewsChallenge_2.ts:4-7` | NoSQL injection | TP | Unvalidated request `id` used as the MongoDB update selector. |
| `noSqlReviewsChallenge_3_correct.ts:10-13` | NoSQL injection | TN | A terminating `typeof id !== 'string'` guard excludes operator objects; message remains a value under fixed `$set`. This does not prove authorization safety. |

### Reviewed DVWA labels

Paths are relative to `vulnerabilities`. SQL database branches and OS-specific
shell branches are grouped into one source/rule case per security variant.

| Source / lines | Category | Result | Label rationale |
| --- | --- | --- | --- |
| `sqli/source/low.php:8-52` | SQL injection | TP | Request `id` interpolated into SQL passed to MySQL/SQLite query APIs. |
| `sqli/source/medium.php:10-49` | SQL injection | TP | Request `id` is quote-escaped but interpolated unquoted into the MySQL/SQLite queries; escaping does not protect an expression or identifier position. |
| `sqli/source/impossible.php:14-57` | SQL injection | TN | Numeric conversion plus prepared SQL and separately bound integer values. |
| `exec/source/low.php:8-15` | Command injection | TP | Request IP appended to a shell command without validation. |
| `exec/source/medium.php:17-24` | Command injection | TP | Removing `&&` and `;` leaves shell operators such as `\|` available. |
| `exec/source/high.php:24-31` | Command injection | TP | Blacklist removes `\| ` but leaves a pipe without a following space available. |
| `exec/source/impossible.php:20-27` | Command injection | TN | Exactly four individually numeric components are rejoined with dots; shell metacharacters are excluded. This is a command-injection control, not full IP validation. |
| `open_redirect/source/low.php:4` | Open redirect | TP | Request value passed directly to the Location header. |
| `open_redirect/source/medium.php:11` | Open redirect | TP | Rejecting `http://` and `https://` still permits a protocol-relative `//host` destination. |
| `open_redirect/source/high.php:5` | Open redirect | TP | Checking for `info.php` anywhere in the value permits an external URL containing that substring. |
| `open_redirect/source/impossible.php:18` | Open redirect | TN | Numeric selector maps only to fixed destination strings. |

### Reproduce JS, TS and PHP

Check out the sources outside the Securock repository, then run from its root:

```sh
git clone https://github.com/OWASP/NodeGoat /tmp/securock-nodegoat
git -C /tmp/securock-nodegoat checkout c5cb68a7084e4ae7dcc60e6a98768720a81841e8
git clone https://github.com/juice-shop/juice-shop /tmp/securock-juice-shop
git -C /tmp/securock-juice-shop checkout 717f5efa886b0417eeecb52378b03cf10567b7e2
git clone https://github.com/digininja/DVWA /tmp/securock-dvwa
git -C /tmp/securock-dvwa checkout a1978a2fed195acd093010af6395f86a281537ca

SECUROCK_NODEGOAT=/tmp/securock-nodegoat \
SECUROCK_JUICE_SHOP=/tmp/securock-juice-shop \
SECUROCK_DVWA=/tmp/securock-dvwa \
go test ./internal/sast -run '^Test(NodeGoat|JuiceShop|DVWA)$' -count=1 -v -timeout 5m
```

Each test prints all case outcomes, per-category TP/FN/FP/TN and incomplete-analysis
counts. Every currently detected vulnerable case is required individually; every
safe control rejects a new false positive. All selected labels are now classified
correctly for their expected rule. The cases remain in the denominator, and any
future miss or false positive fails the regression test; it must not be hidden by
removing a case or weakening a label.

The existing SAST benchmark workflow fetches all three pinned revisions and runs
these tests alongside OWASP Benchmark and PyGoat. Normal `go test ./...` skips
external scans whose environment variable is unset, while the harness unit tests
always run offline. No source is fetched from inside a Go test. Updating an input
requires reviewing its revision, SHA-256, label rationale, line range, measurements
and regression expectations together.
