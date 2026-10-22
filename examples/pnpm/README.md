# Securock pnpm example

Walk through the core loop on a tiny pnpm lockfile: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/pnpm
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query OSV or the registry. The default policy
treats unchecked vulnerabilities and malicious reports as `unknown`,
so `lock` exits `1` unless `--no-fail` is set. `securock.lock` in this
directory is that unknown snapshot for `ms@2.1.3`.

The committed `.npmrc` proves the public npm registry origin (pnpm
lockfiles often omit tarball URLs).

Simulate a dependency change:

```bash
cp after/pnpm-lock.yaml pnpm-lock.yaml
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- pnpm-lock.yaml`.
