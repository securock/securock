# Securock npm example

Walk through the core loop on a tiny npm lockfile: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/npm
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query OSV. The default policy treats unchecked
vulnerabilities as `unknown`, so `lock` exits `1` unless `--no-fail`
is set. `securock.lock` in this directory is that unknown snapshot for
`ms@2.1.3`.

Simulate a dependency change:

```bash
cp after/package-lock.json package-lock.json
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- package-lock.json`.
