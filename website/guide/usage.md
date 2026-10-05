# Usage

```sh
securock scan [path]
securock lock [path]
securock diff [path]
securock verify [path]
securock explain <package> [path]
securock version
```

`scan` is the default when no command is given. `trusted` means the
artifact passed the active policy, not that it is cryptographically
verified.

| Flag | Meaning |
| --- | --- |
| `--network` | `public-only` (default), `offline`, or `allow-all` |
| `--offline` | Skip remote lookups; remote evidence stays `unknown` |
| `--policy` | Path to a policy file |
| `--profile` | Built-in policy: `default` or `strict` (not with `--policy`) |
| `--lock` | Path to `securock.lock` (for `lock` / `diff` / `verify`) |
| `--format` | `text` (default) or `json` |
| `--no-fail` | Always exit `0` |

`--offline` records vulnerability, malicious, capability, behavior,
ownership, provenance, signature, and chain evidence as `unknown`.

`diff` shows what changed. `verify` uses the same comparison and exits
non-zero on trust-relevant drift unless `--no-fail` is set.
`explain` shows digest, source, provenance, signature, trust chain,
ownership, capabilities, vulnerabilities, and malicious-package checks
for one package.

```sh
securock scan --format json
securock diff --format json
securock verify --format json
securock explain react --format json
```

Exit `0` is success / no drift. `1` is a trust violation. `2` is a
configuration or operational error.

Walk through `lock → update → diff → verify` in the [npm example](https://github.com/securock/securock/tree/main/examples/npm).
