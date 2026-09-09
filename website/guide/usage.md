# Usage

```sh
securock scan
securock lock
securock diff
securock verify
securock version
```

`scan` is the default. `--offline` skips OSV and registry lookups and
records vulnerabilities as `unknown`, not trusted. `--network` is
`public-only` (default), `offline`, or `allow-all`. `trusted` means
the artifact passed the active policy, not that it is cryptographically
verified.

`diff` shows what changed. `verify` uses the same comparison and exits
non-zero on trust-relevant drift unless `--no-fail` is set.

```sh
securock diff --format json
securock verify --format json
```

Exit `0` is success / no drift. `1` is a trust violation. `2` is a
configuration or operational error.

Walk through `lock → update → diff → verify` in the [npm example](https://github.com/securock/securock/tree/main/examples/npm).
