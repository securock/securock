# Usage

```sh
securock scan
securock lock
securock diff
securock verify
securock version
```

`scan` is the default. Use `--offline` to skip OSV lookups. `diff` and `verify` exit non-zero on trust drift unless `--no-fail` is set.

Walk through `lock → update → diff → verify` in the [npm example](https://github.com/securock/securock/tree/main/examples/npm).
