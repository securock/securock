# SAST benchmarks

OWASP Benchmark is a development and regression suite for Securock's SAST.
Its labeled failures inform parser, dataflow and library-model improvements.
It is **not a held-out evaluation**, and these scores do not establish parity
with another scanner or predict accuracy on an arbitrary application.

## Revisions and method

| Input | Revision |
| --- | --- |
| Securock before this improvement | `60cd4f3a9713e8c4c9bc2ca78b86d2f68dc072bd` |
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
| Python, current, corrected scope | 447 | 5 | 66 | 712 | 98.89% | 8.48% | +0.9041 |

On identical analysis scopes, the first improvement gained 73 true positives and
removed 67 false positives in Java; Python gained 6 true positives and removed 71
false positives. The collection/XPath work removed another 113 Java false positives
without losing detections, and gained 10 Python true positives while removing 44
false positives. The current round adds 47 Java detections with no new false
positives, and 42 Python detections while removing 21 false positives. The
additional change from Python's old scope is a measurement correction, not an
engine improvement.

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

The current round adds:
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

## Remaining weak categories

| Suite / category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| Java trust boundary | 79 | 4 | 0 | 43 |
| Java weak random | 218 | 0 | 0 | 275 |
| Python command injection | 13 | 0 | 1 | 6 |
| Python code injection | 20 | 0 | 12 | 21 |
| Python path traversal | 60 | 5 | 18 | 85 |
| Python redirect | 13 | 0 | 8 | 13 |
| Python SQL injection | 5 | 0 | 0 | 11 |
| Python XPath injection | 51 | 0 | 5 | 130 |
| Python XSS | 31 | 0 | 11 | 47 |

The Python SQL category has only five vulnerable cases. High aggregate results
must not conceal weak individual categories or missing real-world framework
coverage. Other languages still lack a comparable labeled score. Independent
real-application evaluation remains necessary before making broader accuracy claims.

## Reproduce

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

`.github/workflows/sast-benchmark.yml` uses the pinned revisions on relevant pull
requests, main-branch pushes, a weekly schedule and manual dispatch. Normal
`go test ./...` skips the external suites unless their environment variables are
set. Updating a suite revision requires reviewing the changed labels and counts,
then updating the documented measurements and regression limits together.
