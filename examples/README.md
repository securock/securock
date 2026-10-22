# Examples

Offline fixtures that walk the same loop on different resolvers:

```text
securock lock → bump the language lockfile → diff / verify
```

Each directory includes a tiny dependency tree, an `after/` snapshot with
a version/digest bump, a committed `securock.lock`, and a README.

| Directory | Ecosystem | Resolver | Package |
| --------- | --------- | -------- | ------- |
| [npm](npm/) | npm | npm | `ms@2.1.3` |
| [pnpm](pnpm/) | npm | pnpm | `ms@2.1.3` |
| [yarn](yarn/) | npm | yarn (classic) | `ms@2.1.3` |
| [bun](bun/) | npm | bun | `ms@2.1.3` |
| [uv](uv/) | pypi | uv | `idna@3.10` |
| [poetry](poetry/) | pypi | poetry | `idna@3.10` |
| [go](go/) | go | go | `rsc.io/quote@v1.5.2` |
| [cargo](cargo/) | cargo | cargo | `cfg-if@1.0.0` |

Start with [npm](npm/) if you want the shortest walkthrough. Use the
others when you care about resolver-specific lockfile shapes or
registry provenance (for example pnpm's `.npmrc`).

All fixtures are intended for `--offline` first runs. Online evidence
collection works too once public lookups succeed under your policy.
