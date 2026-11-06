# Securock CocoaPods example

Walk through the core loop on a tiny `Podfile.lock`: lock, change a
dependency, inspect trust drift, then verify.

```bash
cd examples/cocoapods
securock lock --offline --no-fail
securock verify --offline
```

`--offline` does not query anything. OSV has no CocoaPods ecosystem, so
vulnerabilities stay `unknown` even online, and `SPEC CHECKSUMS` are podspec
hashes rather than artifact digests, so no digest is recorded. The default
policy treats unchecked evidence as `unknown`, so `lock` exits `1` unless
`--no-fail` is set.
`securock.lock` in this directory is that unknown snapshot for
`Alamofire@5.8.0`.

Simulate a dependency change:

```bash
cp after/Podfile.lock Podfile.lock
securock diff --offline
securock verify --offline
```

`diff` reports the version change. `verify` fails until you
accept the new tree:

```bash
securock lock --offline
securock verify --offline
```

Restore the original lockfile with `git checkout -- Podfile.lock`.
