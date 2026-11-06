# Securock Julia example

Walk through the core loop on a tiny `Manifest.toml`: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/julia
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query anything. `Manifest.toml` does not say which
registry served a package, so no registry is recorded and OSV is not queried
in `public-only`. `git-tree-sha1` is kept as the resolved reference, not as
a digest, and `Project.toml` supplies the runtime scope. The default policy
treats unchecked evidence as `unknown`, so `lock` exits `1` unless
`--no-fail` is set.
`securock.lock` in this directory is that unknown snapshot for
`URIs@1.5.1`.

Simulate a dependency change:

```bash
cp after/Manifest.toml Manifest.toml
securock diff --offline
securock verify --offline
```

`diff` reports the version and resolved tree change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- Manifest.toml`.
