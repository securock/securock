# Securock npm example

Walk through the core loop on a tiny npm lockfile: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/npm
securock lock --offline
securock verify --offline
```

`securock.lock` in this directory is the snapshot for `ms@2.1.3`.

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
