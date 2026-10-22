# Securock Go example

Walk through the core loop on a tiny Go module: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/go
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query OSV. The default policy treats unchecked
vulnerabilities and malicious reports as `unknown`, so `lock` exits
`1` unless `--no-fail` is set. `securock.lock` in this directory is
that unknown snapshot for `rsc.io/quote@v1.5.2`.

Simulate a dependency change:

```bash
cp after/go.mod go.mod
cp after/go.sum go.sum
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original files with `git checkout -- go.mod go.sum`.
