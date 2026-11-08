# Securock Pipenv example

Walk through the core loop on a tiny `Pipfile.lock`: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/pipenv
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query OSV or the PyPI Integrity API. The default
policy treats unchecked vulnerabilities and malicious reports as
`unknown`, so `lock` exits `1` unless `--no-fail` is set. A digest is
recorded because the entry lists exactly one hash; with several hashes the
digest would stay unknown.
`securock.lock` in this directory is that unknown snapshot for
`idna@3.20`.

Simulate a dependency change:

```bash
cp after/Pipfile.lock Pipfile.lock
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- Pipfile.lock`.
