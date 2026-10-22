# Securock Poetry example

Walk through the core loop on a tiny Poetry lockfile: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/poetry
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query OSV or the PyPI Integrity API. The default
policy treats unchecked vulnerabilities and malicious reports as
`unknown`, so `lock` exits `1` unless `--no-fail` is set.
`securock.lock` in this directory is that unknown snapshot for
`idna@3.19`.

Simulate a dependency change:

```bash
cp after/poetry.lock poetry.lock
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- poetry.lock`.
