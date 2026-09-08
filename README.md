# Securock

Supply-chain trust layer for software dependencies.

Securock reads language lockfiles, evaluates each artifact, and writes a
language-agnostic `securock.lock`. Go is the implementation language; it is not
the only ecosystem Securock understands.

```
package-lock.json
pnpm-lock.yaml
Cargo.lock
go.sum
uv.lock
        ↓
   Dependency
        ↓
    Artifact
        ↓
    Evidence
        ↓
 Trust evaluation
        ↓
   securock.lock
```

## Install

```bash
curl -fsSL https://securock.sh/install | sh
```

Verify a downloaded archive or the extracted binary against GitHub
artifact attestations:

```bash
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```

Or build from source:

```bash
go install github.com/securock/securock/cmd/securock@latest
```

## Usage

```bash
securock scan
securock lock
securock diff
securock verify
securock version
```

`diff` and `verify` are the core loop. `scan` inspects a tree, `lock`
writes `securock.lock`, `diff` shows trust drift after a dependency
change, and `verify` fails when the current tree does not match the
locked trust state.

`scan` is the default command. Use `--offline` to skip OSV lookups.

Walk through `lock → update → diff → verify` in
[`examples/npm`](examples/npm).

## GitHub Action

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  securock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securock/securock@main
        with:
          command: both
```

The action builds the CLI from the same git ref, runs `diff` and/or
`verify`, and posts a `Securock Trust Report` comment on pull requests.

## Lockfile

```yaml
version: 1
artifacts:
  - subject:
      ecosystem: npm
      name: react
    version: 19.2.0
    digest: sha256:...
    source:
      resolver: npm
      registry: https://registry.npmjs.org
    evidence:
      provenance: unknown
      signature: unknown
    trust:
      status: trusted
```

## Supported ecosystems

| Ecosystem | Resolver | Lockfile | Status |
| --- | --- | --- | --- |
| npm | npm | `package-lock.json` | stable target |
| npm | pnpm | `pnpm-lock.yaml` | stable target |
| cargo | cargo | `Cargo.lock` | experimental |
| go | go | `go.sum` | experimental |
| pypi | uv | `uv.lock` | experimental |

## License

Apache-2.0

## Docs

- [securock.dev](https://securock.dev)
- [Lockfile specification](docs/specification.md)
- [Trust model](docs/trust-model.md)
- [Threat model](docs/threat-model.md)
- [GitHub rulesets](docs/github-rulesets.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

