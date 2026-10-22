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

## Beyond lock, diff, and verify

The committed `securock.lock` in each directory is enough for the commands that read the
lockfile, so these work without a network:

```bash
cd examples/npm
securock sbom export > bom.cdx.json              # CycloneDX; add --spec spdx for SPDX
securock sbom verify bom.cdx.json                # no findings: the SBOM matches the lockfile
securock accept known-vulnerability:GHSA-xxxx-xxxx-xxxx \
  --reason "not reachable here" --approver you --expires 30d
securock accept list                             # writes .securock/exceptions.yaml
securock vex export --author "you@example.com"   # OpenVEX for what you accepted
```

These need public lookups, so run them without `--offline`:

```bash
securock audit --reachability                    # severity, fixed versions, dev-only marking
securock audit --min-release-age 7d              # hold back releases newer than a week
securock lock --reachability                     # also record scope and dependencies
```

Delete `.securock/` and `bom.cdx.json` afterwards; they are not part of the fixture.

All fixtures are intended for `--offline` first runs. Online evidence
collection works too once public lookups succeed under your policy.
